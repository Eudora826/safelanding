"""
analysis.py
===========
All the logic for deciding whether a message / link / image is a scam.

The DEFAULT path is fully offline: rule-based checks, no API key, no network.
Every LLM/OCR step below is an OPTIONAL upgrade that degrades gracefully back to
the rule engine when the dependency or the API key is missing.

Three inputs:
  1. URL    -> rule-based heuristics (always offline).
  2. Text   -> rule engine by default; uses OpenAI instead when OPENAI_API_KEY
               is set AND the `openai` package is installed.
  3. Images -> OCR each screenshot (EasyOCR or PaddleOCR, optional deps), then
               feed the text into the same text analysis. Supports MULTIPLE
               images. Falls back to a placeholder when OCR is unavailable or
               finds nothing.

Diagnostics go through the stdlib `logging` module (`logger.debug` for OCR dumps),
so nothing is printed to stdout in normal operation.
"""

import base64
import json
import logging
import os
import re
import tempfile
from urllib.parse import urlparse

# OpenAI is OPTIONAL. The app runs fully offline on rules + the local database.
# If the package isn't installed, or no key is set, text analysis falls back to
# the rule engine automatically (see analyze()).
try:
    from openai import OpenAI
except Exception:  # ImportError, or any partial-install error
    OpenAI = None

from models import AnalyzeRequest, Tactic

logger = logging.getLogger(__name__)

_api_key = os.environ.get("OPENAI_API_KEY")
client = OpenAI(api_key=_api_key) if (_api_key and OpenAI is not None) else None

# ---- OCR engine selector ----
# "easyocr" (light, fast) or "paddle" (PaddleOCR-VL, heavy). Override via env var.
OCR_ENGINE = os.environ.get("OCR_ENGINE", "easyocr")

# Languages EasyOCR recognizes. 'en'=English, 'nl'=Dutch, 'ch_sim'=Chinese.
EASYOCR_LANGS = ["en"]

_ocr_pipeline = None      # PaddleOCR pipeline (lazy)
_easyocr_reader = None    # EasyOCR reader (lazy)


# ============================================================
#  Helper: pick a string by language, fall back to English
# ============================================================
def L(d: dict, lang: str) -> str:
    key = {"Chinese": "zh", "Dutch": "nl", "English": "en"}.get(lang, "en")
    return d.get(key, d["en"])


# ============================================================
#  Part 1: real URL checks (rules, not a mock)
# ============================================================
OFFICIAL_DOMAINS = {
    "funda": "funda.nl",
    "pararius": "pararius.nl",
    "kamernet": "kamernet.nl",
    "marktplaats": "marktplaats.nl",
    "ing": "ing.nl",
    "abnamro": "abnamro.nl",
    "rabobank": "rabobank.nl",
    "postnl": "postnl.nl",
}

SUSPICIOUS_WORDS = [
    "secure", "verify", "verification", "login", "signin", "pay", "payment",
    "confirm", "account", "update", "customs", "fee", "claim", "reward", "portal",
]

RISKY_TLDS = (".info", ".xyz", ".top", ".online", ".site", ".click", ".live", ".buzz")

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
URL_IN_TEXT_RE = re.compile(r"https?://[^\s)<>\"']+", re.IGNORECASE)


def check_url(raw_url: str, lang: str) -> list[tuple[Tactic, int]]:
    """Run real heuristic checks on one URL. Returns (signal, weight) pairs."""
    findings: list[tuple[Tactic, int]] = []
    raw_url = raw_url.strip()
    if not raw_url:
        return findings

    parsed = urlparse(raw_url if "://" in raw_url else "http://" + raw_url)
    host = (parsed.hostname or "").lower()
    scheme = parsed.scheme.lower()

    if scheme != "https":
        findings.append((Tactic(
            name=L({"en": "Not using HTTPS", "zh": "没有用 HTTPS", "nl": "Geen HTTPS"}, lang),
            snippet=scheme + "://...",
            explanation=L({
                "en": "The link is not secure (no https). Legit payment/login pages almost always use https.",
                "zh": "链接不安全(不是 https)。正规的支付/登录页面几乎都用 https。",
                "nl": "De link is niet beveiligd (geen https). Echte betaal-/loginpagina's gebruiken bijna altijd https.",
            }, lang),
        ), 10))

    if IP_RE.match(host):
        findings.append((Tactic(
            name=L({"en": "Raw IP address", "zh": "直接用 IP 地址", "nl": "Kaal IP-adres"}, lang),
            snippet=host,
            explanation=L({
                "en": "Real companies use a domain name, not a bare IP address.",
                "zh": "正规公司用域名,而不是裸露的 IP 地址。",
                "nl": "Echte bedrijven gebruiken een domeinnaam, geen kaal IP-adres.",
            }, lang),
        ), 25))

    if "xn--" in host:
        findings.append((Tactic(
            name=L({"en": "Disguised characters", "zh": "伪装字符域名", "nl": "Verhulde tekens"}, lang),
            snippet=host,
            explanation=L({
                "en": "The domain uses encoded characters to look like a real brand.",
                "zh": "域名用了编码字符来伪装成真品牌。",
                "nl": "Het domein gebruikt gecodeerde tekens om op een echt merk te lijken.",
            }, lang),
        ), 25))

    for brand, official in OFFICIAL_DOMAINS.items():
        if brand in host and not (host == official or host.endswith("." + official)):
            findings.append((Tactic(
                name=L({"en": "Fake brand domain", "zh": "仿冒品牌域名", "nl": "Nep merkdomein"}, lang),
                snippet=host,
                explanation=L({
                    "en": f"This looks like '{brand}' but the real address is {official}. Scammers copy brand names into fake domains.",
                    "zh": f"这看起来像 '{brand}',但官方地址其实是 {official}。骗子把品牌名塞进山寨域名。",
                    "nl": f"Dit lijkt op '{brand}', maar het echte adres is {official}. Oplichters kopiëren merknamen in nepdomeinen.",
                }, lang),
            ), 35))
            break

    hit_words = [w for w in SUSPICIOUS_WORDS if w in host]
    if hit_words:
        findings.append((Tactic(
            name=L({"en": "Suspicious words in domain", "zh": "域名含可疑词", "nl": "Verdachte woorden in domein"}, lang),
            snippet=", ".join(hit_words[:3]),
            explanation=L({
                "en": "Words like 'secure', 'verify', 'pay' in the domain itself are a common phishing trick.",
                "zh": "域名里出现 'secure'、'verify'、'pay' 这类词,是常见的钓鱼套路。",
                "nl": "Woorden als 'secure', 'verify', 'pay' in het domein zelf zijn een veelvoorkomende phishing-truc.",
            }, lang),
        ), 20))

    if host.endswith(RISKY_TLDS):
        findings.append((Tactic(
            name=L({"en": "Unusual domain ending", "zh": "不常见的域名后缀", "nl": "Ongebruikelijke domeinextensie"}, lang),
            snippet="." + host.split(".")[-1],
            explanation=L({
                "en": "This type of domain ending is cheap and often abused by scammers. Not proof alone, but a yellow flag.",
                "zh": "这类后缀便宜、常被骗子滥用。单独不算铁证,但值得警惕。",
                "nl": "Dit soort extensie is goedkoop en wordt vaak misbruikt. Geen bewijs op zich, maar een waarschuwing.",
            }, lang),
        ), 8))

    return findings


# ============================================================
#  Part 2a: text via OpenAI (real model)
# ============================================================
TEXT_LLM_SYSTEM = """
You are a privacy-aware rental-scam risk detector for non-native speakers and newly arrived international students searching for housing online.

---

TASK
Analyse a rental-related message and identify manipulation tactics or cyber-enabled fraud signals.

---

FRAUD SIGNALS TO DETECT
- Urgent payment pressure
- Deposit or rent required before viewing
- Landlord refuses or avoids in-person meeting
- Landlord claims to be abroad
- Request for passport, BSN, DigiD, bank details, or other sensitive documents
- Suspicious payment links, private IBANs, or off-platform payment requests
- Conversation moved away from a trusted platform
- Fake official process, fake agency, or fake verification request
- Unrealistic rent, too-good-to-be-true offer, or inconsistent details

---

OUTPUT FORMAT
Respond with ONLY a valid JSON object. No markdown, no backticks, no comments, no extra text.

Schema:
{
  "tactics": [
    {
      "name": "<short label>",
      "snippet": "<verbatim text copied from the user message>",
      "explanation": "<why this is risky for an international student or non-native speaker>",
      "weight": <integer 0-40>
    }
  ]
}

If the message looks legitimate or lacks sufficient evidence, return: {"tactics": []}

---

FIELD RULES
- snippet     -> must be copied verbatim from the input; never invented or paraphrased
- name        -> short label only
- explanation -> explain the risk in plain language targeted at a non-native speaker
- weight      -> integer 0-40 (see scale below)
- name + explanation -> write in this language: {lang}
- Do not output a risk score for the whole message; only output per-tactic entries
- If personal data appears in the message, do not repeat more than the exact snippet needed

---

WEIGHT SCALE
1-10  : Weak signal - possibly normal, but worth noticing
11-25 : Medium signal - suspicious in context
26-40 : Strong red flag - likely to push unsafe behaviour (clicking, paying, sharing documents)

---

CONSTRAINTS
- Do not claim that a person is definitely a scammer or criminal
- Focus on risky message patterns, not on identifying or accusing individuals
- Do not over-flag normal rental communication
- Do not mark a message unsafe solely because it mentions rent, deposit, viewing, or documents
- Do not treat every link as suspicious unless surrounding context creates risk
- Do not infer missing context (e.g. do not assume the landlord is fake without evidence)
- Do not include safe advice or any text outside the JSON object

---

WORKFLOW
1. Determine whether the message is rental-related; if not, return {"tactics": []}
2. Scan for explicit red flags listed above
3. For each red flag, extract the shortest relevant verbatim snippet
4. Assign a weight based on how strongly the tactic could pressure the user into clicking, paying, or sharing sensitive information
5. Return only the JSON object following the schema above
"""


OCR_CLEANUP_SYSTEM = """
You are a text-restoration assistant. You receive raw text extracted by OCR from a screenshot of a rental message. OCR output is noisy: characters are misread (0 vs o, 1/l vs I, rn vs m), apostrophes are dropped (Im -> I'm, isn"t -> isn't), words are split or merged, and line breaks are wrong.

YOUR JOB
Reconstruct the message as the sender most likely wrote it, so a human can read it cleanly.

RULES
- Fix ONLY OCR artifacts: character confusions, dropped apostrophes, broken spacing, and wrong line breaks. Restore an obviously missing word only when the OCR clearly dropped it.
- Keep the sender's own wording, tone, and language. Do NOT translate. Do NOT paraphrase, summarise, shorten, or "improve" their grammar or style.
- Do NOT add greetings, labels, explanations, or any commentary of your own.
- Preserve the original language of the message (English, Dutch, or Chinese).
- Group the text into natural paragraphs with normal sentence punctuation.

OUTPUT
Return ONLY the cleaned message text. No preamble, no markdown, no quotes, no labels.
If there is no readable content, return an empty string.
"""


def clean_ocr_text(raw_text: str, lang: str) -> str:
    """Repair OCR noise into a readable message. Falls back to raw text on any failure.

    Runs as a separate, lightweight LLM call so the downstream scam analysis (and
    the snippet highlighting in the UI) all operate on clean, readable text. If
    there is no OpenAI client or the call fails, the original OCR text is returned
    unchanged so the app keeps working offline.
    """
    if client is None or not raw_text.strip():
        return raw_text.strip()
    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": OCR_CLEANUP_SYSTEM},
                {"role": "user", "content": raw_text},
            ],
            temperature=0,
        )
        cleaned = (resp.choices[0].message.content or "").strip()
        return cleaned or raw_text.strip()
    except Exception as e:
        logger.warning("OCR cleanup failed, using raw text: %s", e)
        return raw_text.strip()


def check_text_llm(text: str, lang: str) -> list[tuple[Tactic, int]]:
    """Same input/output contract as check_text(), but uses OpenAI.
    Raises if there's no client or the call/parse fails -> caller falls back."""
    if client is None:
        raise RuntimeError("No OPENAI_API_KEY set")

    system = TEXT_LLM_SYSTEM.replace("{lang}", lang)

    resp = client.chat.completions.create(
        model="gpt-4o-mini",                       # change to a model your account can use
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": text},
        ],
        response_format={"type": "json_object"},
    )

    raw = resp.choices[0].message.content or ""
    data = json.loads(raw)

    findings: list[tuple[Tactic, int]] = []
    for t in data.get("tactics", []):
        findings.append((
            Tactic(name=t["name"], snippet=t.get("snippet", ""), explanation=t["explanation"]),
            int(t.get("weight", 20)),
        ))
    return findings


# ============================================================
#  Part 2b: text rule-based fallback (smart mock)
# ============================================================
RENTAL_RULES = [
    {
        "patterns": ["abroad", "overseas", "out of the country", "cannot meet", "can't meet",
                     "not in person", "send the keys", "by post", "by mail", "currently away", "another city"],
        "weight": 30,
        "name": {"en": "Landlord won't meet in person", "zh": "房东不肯当面见", "nl": "Verhuurder wil niet persoonlijk afspreken"},
        "explanation": {
            "en": "A landlord who is 'abroad' and wants to mail you the keys is the #1 rental scam pattern. Always view the place and meet in person first.",
            "zh": "房东声称'在国外'、要把钥匙寄给你,是最典型的租房骗局。一定要先看房、当面见人。",
            "nl": "Een verhuurder die in het buitenland is en de sleutels wil opsturen is hét patroon van huurfraude. Bezichtig altijd eerst persoonlijk.",
        },
    },
    {
        "patterns": ["deposit", "holding fee", "reserve", "first month", "wire", "western union",
                     "iban", "transfer", "borg", "aanbetaling"],
        "weight": 30,
        "name": {"en": "Pay before viewing", "zh": "看房前先交钱", "nl": "Betalen vóór bezichtiging"},
        "explanation": {
            "en": "Being asked to transfer a deposit or 'holding fee' before you've seen the place or signed anything is a major red flag.",
            "zh": "还没看房、没签任何东西就被要求转押金或'订金',是重大危险信号。",
            "nl": "Gevraagd worden om een borg of 'reserveringskosten' over te maken vóór bezichtiging is een groot alarmsignaal.",
        },
    },
    {
        "patterns": ["within 24 hours", "within 12 hours", "today", "immediately", "right now",
                     "limited spots", "other interested", "many interested", "expires", "act now", "asap"],
        "weight": 20,
        "name": {"en": "Artificial urgency", "zh": "制造紧迫感", "nl": "Kunstmatige urgentie"},
        "explanation": {
            "en": "Pressure like 'pay today' or 'others are interested' is designed to stop you from checking carefully.",
            "zh": "'今天就付'、'还有别人在抢'这类施压,就是为了让你来不及仔细核实。",
            "nl": "Druk als 'betaal vandaag' of 'anderen hebben interesse' is bedoeld om je niet zorgvuldig te laten controleren.",
        },
    },
    {
        "patterns": ["password", "verify your", "login details", "confirm your identity", "card details", "pincode"],
        "weight": 25,
        "name": {"en": "Asks for credentials", "zh": "索取账号/密码", "nl": "Vraagt om inloggegevens"},
        "explanation": {
            "en": "Real platforms never ask you to confirm passwords or card details through an email link.",
            "zh": "正规平台绝不会通过邮件链接要你'验证密码'或卡号。",
            "nl": "Echte platforms vragen je nooit om wachtwoorden of kaartgegevens via een e-maillink.",
        },
    },
    {
        "patterns": ["payment portal", "secure payment", "verified by", "pre-approved", "pre approved"],
        "weight": 20,
        "name": {"en": "Fake official process", "zh": "伪装官方流程", "nl": "Nep officieel proces"},
        "explanation": {
            "en": "Scammers fake 'secure payment portals' and 'verified' badges to look legitimate.",
            "zh": "骗子伪造'安全支付门户'、'已验证'标识来显得正规。",
            "nl": "Oplichters faken 'beveiligde betaalportalen' en 'geverifieerd'-badges om legitiem te lijken.",
        },
    },
]


def _find_snippet(text: str, keyword: str) -> str:
    low = text.lower()
    i = low.find(keyword.lower())
    if i == -1:
        return keyword
    start = max(0, i - 12)
    end = min(len(text), i + len(keyword) + 18)
    snippet = text[start:end].strip()
    return ("..." if start > 0 else "") + snippet + ("..." if end < len(text) else "")


def check_text(text: str, lang: str) -> list[tuple[Tactic, int]]:
    findings: list[tuple[Tactic, int]] = []
    if not text.strip():
        return findings
    low = text.lower()
    for rule in RENTAL_RULES:
        for kw in rule["patterns"]:
            if kw in low:
                findings.append((Tactic(
                    name=L(rule["name"], lang),
                    snippet=_find_snippet(text, kw),
                    explanation=L(rule["explanation"], lang),
                ), rule["weight"]))
                break
    for found_url in URL_IN_TEXT_RE.findall(text):
        findings.extend(check_url(found_url, lang))
    return findings


# ============================================================
#  Part 3a: OCR - read text out of an uploaded image
# ============================================================
def _extract_text_from_res(res) -> str:
    """Pull recognized text out of a PaddleOCR result object (shapes vary by version)."""
    md = getattr(res, "markdown", None)
    if isinstance(md, str) and md.strip():
        return md
    if isinstance(md, dict):
        for key in ("markdown_texts", "text", "markdown"):
            v = md.get(key)
            if isinstance(v, str) and v.strip():
                return v
        parts = [v for v in md.values() if isinstance(v, str)]
        if parts:
            return "\n".join(parts)
    j = getattr(res, "json", None)
    if isinstance(j, dict):
        blob = j.get("res", j)
        if isinstance(blob, dict):
            for key in ("rec_texts", "texts", "text"):
                v = blob.get(key)
                if isinstance(v, list) and v:
                    return "\n".join(str(x) for x in v)
                if isinstance(v, str) and v.strip():
                    return v
    return ""


def ocr_image_paddle(image_base64: str) -> str:
    """Decode base64 -> temp PNG -> PaddleOCR -> recognized text."""
    global _ocr_pipeline
    img_bytes = base64.b64decode(image_base64)
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            tmp.write(img_bytes)
            tmp_path = tmp.name
        if _ocr_pipeline is None:
            from paddleocr import PaddleOCRVL
            _ocr_pipeline = PaddleOCRVL(pipeline_version="v1.6")
        output = _ocr_pipeline.predict(tmp_path)
        texts = []
        for res in output:
            t = _extract_text_from_res(res)
            if t.strip():
                texts.append(t)
        return "\n".join(texts).strip()
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)


def ocr_image_easyocr(image_base64: str) -> str:
    """Decode base64 -> EasyOCR (reads bytes directly) -> recognized text."""
    global _easyocr_reader
    img_bytes = base64.b64decode(image_base64)
    if _easyocr_reader is None:
        import easyocr
        _easyocr_reader = easyocr.Reader(EASYOCR_LANGS)
    lines = _easyocr_reader.readtext(img_bytes, detail=0)
    return "\n".join(lines).strip()


def ocr_image(image_base64: str) -> str:
    """Read text from one image using whichever engine OCR_ENGINE selects."""
    if OCR_ENGINE == "paddle":
        return ocr_image_paddle(image_base64)
    return ocr_image_easyocr(image_base64)


# ============================================================
#  Part 3b: image placeholder (used when OCR fails/empty)
# ============================================================
def check_image(lang: str) -> list[tuple[Tactic, int]]:
    return [(Tactic(
        name=L({"en": "[Demo] Image received", "zh": "[演示] 已收到图片", "nl": "[Demo] Afbeelding ontvangen"}, lang),
        snippet="image",
        explanation=L({
            "en": "OCR is unavailable or found no readable text in this image.",
            "zh": "OCR 不可用,或这张图里没读到可识别的文字。",
            "nl": "OCR is niet beschikbaar of vond geen leesbare tekst in deze afbeelding.",
        }, lang),
    ), 15)]

# ============================================================
#  Part 4: localized "how to spot it yourself" tips
# ============================================================
def _spotting_tips(lang: str, checked_url: bool) -> list[str]:
    tips = {
        "en": [
            "Always view the property and meet the landlord in person before paying anything.",
            "Never transfer a deposit before signing a contract you have read.",
            "Search the listing photos online - scammers reuse photos from real listings.",
            "Check the website address letter by letter against the official one.",
        ],
        "zh": [
            "付任何钱之前,一定先看房、当面见房东。",
            "在看过、签过合同之前,绝不要先转押金。",
            "把房源照片拿去网上搜——骗子常盗用真实房源的照片。",
            "把网址逐字母和官方域名比对。",
        ],
        "nl": [
            "Bezichtig de woning en ontmoet de verhuurder altijd persoonlijk vóór je betaalt.",
            "Maak nooit een borg over voordat je een gelezen contract hebt ondertekend.",
            "Zoek de foto's online op - oplichters hergebruiken foto's van echte advertenties.",
            "Controleer het webadres letter voor letter tegen het officiële.",
        ],
    }
    key = {"Chinese": "zh", "Dutch": "nl", "English": "en"}.get(lang, "en")
    return tips[key]


# ============================================================
#  Entry point: signal collection (used by fusion.py)
# ============================================================
def collect_signals(req: "AnalyzeRequest") -> tuple[list[tuple["Tactic", int]], list[str], str]:
    """Run the live detectors and ALSO return the combined plain text.

    Returns (findings, inputs_analyzed, combined_text). The combined text is
    the user's message plus the URL plus any OCR-extracted text from images,
    so the database layer can match patterns / reported identifiers against
    everything the user submitted, not just the typed message.
    """
    lang = req.native_language
    findings: list[tuple[Tactic, int]] = []
    inputs: list[str] = []
    text_parts: list[str] = []

    if req.text.strip():
        inputs.append("text")
        text_parts.append(req.text)
        try:
            findings += check_text_llm(req.text, lang)
        except Exception as e:
            logger.info("LLM text analysis unavailable, using rule engine: %s", e)
            findings += check_text(req.text, lang)

    if req.url.strip():
        inputs.append("url")
        text_parts.append(req.url)
        findings += check_url(req.url, lang)

    real_images = [img for img in req.images_base64 if img.strip()]
    if real_images:
        inputs.append(f"image x{len(real_images)}")
        for idx, img_b64 in enumerate(real_images, start=1):
            # OCR once here, reuse the text for both findings and DB retrieval.
            try:
                ocr_text = ocr_image(img_b64)
                logger.debug("OCR result [image %d]: %s", idx, ocr_text)
                ocr_text = clean_ocr_text(ocr_text, lang)
                logger.debug("OCR cleaned [image %d]: %s", idx, ocr_text)
                if ocr_text.strip():
                    text_parts.append(ocr_text)
                    try:
                        findings += check_text_llm(ocr_text, lang)
                    except Exception as e:
                        logger.info("LLM unavailable for image %d, using rule engine: %s", idx, e)
                        findings += check_text(ocr_text, lang)
                else:
                    findings += check_image(lang)
            except Exception as e:
                logger.warning("OCR failed for image %d, using placeholder: %s", idx, e)
                findings += check_image(lang)

    combined_text = "\n".join(text_parts).strip()
    return findings, inputs, combined_text
