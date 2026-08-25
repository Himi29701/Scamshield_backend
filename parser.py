"""
Parses raw user input (a pasted email, SMS, WhatsApp text, or bare URL)
into a structured shape the rest of the pipeline can work with.
"""
import re
import tldextract

URL_RE = re.compile(r'(https?://[^\s<>"\']+|www\.[^\s<>"\']+)', re.IGNORECASE)
PHONE_RE = re.compile(r'(\+?\d[\d\-\s()]{7,}\d)')
EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

URGENCY_WORDS = [
    "urgent", "immediately", "verify your account", "suspended", "act now",
    "limited time", "click here", "confirm your identity", "unusual activity",
    "your account will be", "winner", "claim your", "final notice", "locked",
]


def classify_input_type(raw_text: str) -> str:
    text = raw_text.strip()
    if text.lower().startswith(("http://", "https://", "www.")) and " " not in text:
        return "url"
    if EMAIL_RE.search(text) and ("subject:" in text.lower() or "from:" in text.lower()):
        return "email"
    if PHONE_RE.search(text) and len(text) < 500:
        return "sms"
    return "message"


def normalize_url(u: str) -> str:
    if u.startswith("www."):
        u = "https://" + u
    return u.rstrip(".,;:!?)")


def extract_domain(url: str) -> str:
    ext = tldextract.extract(url)
    return ".".join(part for part in [ext.domain, ext.suffix] if part)


def parse_input(raw_text: str) -> dict:
    input_type = classify_input_type(raw_text)
    urls = [normalize_url(u) for u in URL_RE.findall(raw_text)]
    phones = PHONE_RE.findall(raw_text)
    emails = EMAIL_RE.findall(raw_text)
    hits = [w for w in URGENCY_WORDS if w in raw_text.lower()]

    domains = list({extract_domain(u) for u in urls if extract_domain(u)})

    return {
        "input_type": input_type,
        "raw_text": raw_text,
        "urls": urls,
        "domains": domains,
        "phones": phones,
        "sender_emails": emails,
        "urgency_signals": hits,
    }
