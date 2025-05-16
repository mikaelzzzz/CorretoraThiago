# FastAPI · OCR · ZapSign · Notion  ── Corretora 3.0
# ------------------------------------------------------------
import os, io, re, json, hmac, hashlib, datetime, logging, requests
import pdfplumber, pytesseract
from typing import List, Dict, Any
from fastapi import FastAPI, BackgroundTasks, HTTPException, Request
from notion_client import Client as Notion, APIResponseError

# ─────────────────── logging básico ───────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# ─────────────────── variáveis de ambiente (.env) ─────────────
NOTION_TOKEN   = os.getenv("NOTION_TOKEN")        # secret_***
NOTION_DB_ID   = os.getenv("NOTION_DB_ID")        # ID do database
ZAPSIGN_TOKEN  = os.getenv("ZAPSIGN_TOKEN")       # Token xxxxx
ZAP_SECRET     = os.getenv("ZAP_SECRET")          # assinatura webhook
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")      # opcional GPT

if not (NOTION_TOKEN and NOTION_DB_ID and ZAPSIGN_TOKEN):
    raise RuntimeError("Configure NOTION_TOKEN, NOTION_DB_ID, ZAPSIGN_TOKEN")

# nome exato da coluna Select no Notion
STATUS_PROP = "Status Assinatura"

notion = Notion(auth=NOTION_TOKEN)
app    = FastAPI()

# ─────────────────── carrega esquema de propriedades ──────────
db_schema = notion.databases.retrieve(NOTION_DB_ID)["properties"]
def has_prop(name: str) -> bool:
    return name in db_schema

# ─────────────────── dicionários de normalização ──────────────
SEGURADORAS = {
    "tokio": "Tokio Marine", "tokio marine": "Tokio Marine",
    "porto": "Porto Seguro", "porto seguro": "Porto Seguro",
    "azul": "Azul Seguros", "azul seguros": "Azul Seguros",
    "sulamerica": "Sul America", "sul america": "Sul America",
    "allianz": "Allianz"
}
TIPOS = {
    "auto": "Automóvel", "automóvel": "Automóvel", "automovel": "Automóvel",
    "vida": "Seguro de Vida", "seguro de vida": "Seguro de Vida",
    "empresa": "Empresa",
    "saude": "Saude", "saúde": "Saude",
    "residencial": "Residencial",
    "bike": "Bicicleta", "bicicleta": "Bicicleta",
    "celular": "Celular",
    "notebook": "Notebook"
}

# ─────────────────── utils OCR / REGEX / HELPERS ──────────────
def download(url: str) -> bytes:
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    return r.content

def ocr_text(pdf: bytes) -> str:
    text = ""
    with pdfplumber.open(io.BytesIO(pdf)) as doc:
        for pg in doc.pages:
            text += pg.extract_text() or ""
    if not text.strip():                              # fallback imagem
        from pdf2image import convert_from_bytes
        for img in convert_from_bytes(pdf):
            text += pytesseract.image_to_string(img, lang="por")
    return text

def first(rgx: str, txt: str, n: int = 1):
    it = re.finditer(rgx, txt, re.I | re.S)
    for _ in range(n - 1):
        next(it, None)
    m = next(it, None)
    return (m.group(1).strip() if m else "")

def normalize(val: str, table: dict) -> str:
    lv = val.lower()
    for k, v in table.items():
        if k in lv:
            return v
    return val

def br_to_iso(date_br: str):
    if not date_br:
        return None
    try:
        return datetime.datetime.strptime(date_br, "%d/%m/%Y").date().isoformat()
    except ValueError:
        return None

def rt(txt: str) -> Dict[str, Any]:
    return {"rich_text": [{"text": {"content": txt}}]}

def safe(prop: Dict[str, Any], key: str, default=""):
    """extrai plain_text sem quebrar"""
    try:
        return prop[key][0]["plain_text"]
    except (KeyError, IndexError, TypeError):
        return default

def parse_pdf(txt: str) -> dict:
    data = {
        "id": first(r"N[oº]?\s*Proposta[^0-9]*(\d{4,})", txt),
        "nome": first(r"(?:Proponent[ea]|Segurado)[^\n]*\n([^\n]+)", txt),
        "email": first(r"[\w\.-]+@[\w\.-]+\.[A-Za-z]{2,}", txt),
        "fone": first(r"\(?\d{2}\)?\s?\d{4,5}[- ]?\d{4}", txt),
        "vig1": first(r"Vig[êe]ncia[^0-9]*(\d{2}/\d{2}/\d{4})", txt, 1),
        "vig2": first(r"Vig[êe]ncia[^0-9]*(\d{2}/\d{2}/\d{4})", txt, 2),
        "tipo": first(r"Tipo Segur[oa]?:\s*([A-Za-z ]+)", txt),
        "seg": first(r"(Tokio Marine|Porto Seguro|Azul Seguros|Sul America|Allianz)", txt),
        "modelo": first(r"Modelo[:\s]*([\w\- ]+)", txt),
        "ano": first(r"Ano modelo[:\s]*(\d{4})", txt),
        "placa": first(r"Placa[:\s]*([A-Z]{3}\-?[0-9A-Z]{4})", txt),
        "chassi": first(r"Chassi[:\s]*([A-Z0-9]{8,})", txt),
    }
    data["tipo"] = normalize(data["tipo"], TIPOS)
    data["seg"] = normalize(data["seg"], SEGURADORAS)
    return data

# ─────────────────── GPT fallback opcional ────────────────────
def gpt_extract(txt: str) -> dict:
    if not OPENAI_API_KEY:
        return {}
    import openai, textwrap, json as js
    openai.api_key = OPENAI_API_KEY
    prompt = textwrap.dedent(f"""
      Extraia JSON com: id_proposta,nome,email,telefone,
      vig_inicio,vig_fim,seguradora,tipo,modelo,ano,placa,chassi
      Texto: \"\"\"{txt[:3500]}\"\"\"""")
    rsp = openai.ChatCompletion.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1)
    return js.loads(rsp.choices[0].message.content)

# ─────────────────── ZapSign integração ───────────────────────
def create_zapsign(url, nome, email, fone, id_) -> str:
    payload = {
        "name": f"Proposta {id_} - {nome}",
        "url_pdf": url,
        "signers": [{
            "name": nome,
            "email": email,
            "phone_country": "55",
            "phone_number": re.sub(r"\D", "", fone)[:11],
            "send_automatic_email": True
        }],
        "external_id": id_,
        "lang": "pt-br",
        "send_automatic_email": True
    }
    r = requests.post(
        "https://api.zapsign.com.br/api/v1/docs",
        json=payload,
        headers={
            "Authorization": f"Token {ZAPSIGN_TOKEN}",
            "Content-Type": "application/json"
        }
    )
    r.raise_for_status()
    return r.json()["token"]

# ─────────────────── helpers Notion seguros ───────────────────
def update_page_safe(page_id: str, props: dict):
    """atualiza apenas propriedades existentes e não vazias"""
    valid_props = {}
    for k, v in props.items():
        if not has_prop(k):
            logging.warning("Propriedade %s não existe no DB.", k)
            continue
        if v is None or v == "" or v == {}:
            continue
        valid_props[k] = v
    if not valid_props:
        return
    try:
        notion.pages.update(page_id, properties=valid_props)
    except APIResponseError as e:
        logging.error("Notion API error: %s", e)
        if has_prop("OBS"):
            notion.pages.update(page_id, properties={
                "OBS": rt(f"Erro ao escrever {list(valid_props.keys())}: {e}")
            })

# ─────────────────── /ocr – botão “Preencher do PDF” ──────────
@app.post("/ocr")
def ocr_button(payload: dict, bg: BackgroundTasks):
    page_id = payload["data"]["id"]

    def job():
        try:
            page = notion.pages.retrieve(page_id)
            files: List[Dict[str, Any]] = page["properties"]["Arquivo PDF"]["files"]
            if not files:
                update_page_safe(page_id, {
                    STATUS_PROP: {"select": {"name": "Sem arquivo"}}
                })
                return

            for f in files:
                txt = ocr_text(download(f["file"]["url"]))
                data = parse_pdf(txt)
                if not data["id"]:
                    data |= gpt_extract(txt)   # fallback LLM

                update_page_safe(page_id, {
                    "ID Proposta": rt(data["id"]),
                    "Título": rt(data["nome"]),
                    "Email": {"email": data["email"]},
                    "WhatsApp": rt(data["fone"]),
                    "Data de Fechamento": {"date": {"start": br_to_iso(data["vig1"])}},
                    "Fim da Vigência": {"date": {"start": br_to_iso(data["vig2"])}},
                    "Tipo de Seguro": {"select": {"name": data["tipo"] or "Outro"}},
                    "Seguradora": {"select": {"name": data["seg"] or "Outra"}},
                    "Modelo do Carro": rt(data["modelo"]),
                    "Ano do Carro": rt(data["ano"]),
                    "Placa": rt(data["placa"]),
                    "Chassis": rt(data["chassi"]),
                    STATUS_PROP: {"select": {"name": "Dados OK"}}
                })

        except Exception as e:
            logging.exception("Falha OCR")
            update_page_safe(page_id, {
                STATUS_PROP: {"select": {"name": "Erro OCR"}}
            })

    bg.add_task(job)
    return {"ok": "OCR em andamento"}

# ─────────────────── /send – botão “Enviar p/ Assinatura” ─────
@app.post("/send")
def send_button(payload: dict, bg: BackgroundTasks):
    page_id = payload["data"]["id"]

    def job():
        try:
            page = notion.pages.retrieve(page_id)
            props = page["properties"]
            files = props["Arquivo PDF"]["files"]
            if not files:
                update_page_safe(page_id, {
                    STATUS_PROP: {"select": {"name": "Sem arquivo"}}
                })
                return

            f = files[0]
            get_rich = lambda p: safe(props.get(p, {}), "rich_text")
            token = create_zapsign(
                f["file"]["url"],
                nome=get_rich("Título"),
                email=props.get("Email", {}).get("email", ""),
                fone=get_rich("WhatsApp"),
                id_=get_rich("ID Proposta")
            )
            update_page_safe(page_id, {
                "ZapSign ID": rt(token),
                STATUS_PROP: {"select": {"name": "Enviado"}}
            })

        except Exception as e:
            logging.exception("Falha envio ZapSign")
            update_page_safe(page_id, {
                STATUS_PROP: {"select": {"name": "Erro Envio"}}
            })

    bg.add_task(job)
    return {"ok": "enviando ZapSign"}

# ─────────────────── webhook /zapsign – doc_signed ────────────
def valid_sig(raw: bytes, sig: str) -> bool:
    if not ZAP_SECRET:
        return True
    mac = hmac.new(ZAP_SECRET.encode(), raw, hashlib.sha256)
    return hmac.compare_digest("sha256=" + mac.hexdigest(), sig)

@app.post("/zapsign")
async def zapsign_webhook(req: Request):
    raw = await req.body()
    if not valid_sig(raw, req.headers.get("X-Hub-Signature", "")):
        raise HTTPException(401, "Assinatura inválida")

    data = await req.json()
    if data.get("event_type") != "doc_signed":
        return {"ignored": data.get("event_type")}

    ext_id = str(data.get("external_id", "")).strip()
    if not ext_id:
        return {"error": "external_id vazio"}

    res = notion.databases.query(
        database_id=NOTION_DB_ID,
        filter={"property": "ID Proposta",
                "rich_text": {"equals": ext_id}},
        page_size=1
    )
    if not res["results"]:
        logging.warning("Página não encontrada para ID Proposta=%s", ext_id)
        return {"error": "page not found"}

    page_id = res["results"][0]["id"]
    try:
        update_page_safe(page_id, {
            STATUS_PROP: {"select": {"name": "Assinado"}}
        })
    except Exception as e:
        logging.exception("Erro atualizar para Assinado")

    return {"ok": "status Assinado"}
