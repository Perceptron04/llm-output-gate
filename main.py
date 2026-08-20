"""
LLM Output Handling Gate  (OWASP LLM05)
POST /sanitize-output
Deterministic, no LLM, no phrase-list — only fixed rules, applied in a fixed order.
"""

import re
from urllib.parse import urlsplit, unquote
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

ALLOWED_HOSTS = {"cdn-4k518y6.example", "app-ggtqy5w.example"}
VALID_CHANNELS = {"html", "markdown", "url", "sql", "shell"}
MAX_LEN = 20000

# ---------------------------------------------------------------------------
# Decoding (used only for the ENCODED_PAYLOAD pre-check)
# ---------------------------------------------------------------------------

_ENTITY_RE = re.compile(r"&(#x[0-9a-fA-F]+|#[0-9]+|lt|gt|quot|apos|amp);")
_UESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")

_NAMED = {"lt": "<", "gt": ">", "quot": '"', "apos": "'", "amp": "&"}


def _decode_entity(m: "re.Match") -> str:
    token = m.group(1)
    if token.startswith("#x") or token.startswith("#X"):
        return chr(int(token[2:], 16))
    if token.startswith("#"):
        return chr(int(token[1:]))
    return _NAMED[token]


def decode_once(s: str) -> str:
    # 1) percent-escapes
    step1 = unquote(s)
    # 2) HTML entities (numeric + the 5 named ones)
    step2 = _ENTITY_RE.sub(_decode_entity, step1)
    # 3) \uXXXX escapes
    step3 = _UESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), step2)
    return step3


# ---------------------------------------------------------------------------
# Low-level detectors
# ---------------------------------------------------------------------------

_SCRIPT_TAG_RE = re.compile(r"<\s*(script|iframe|object|embed)\b", re.IGNORECASE)
_EVENT_HANDLER_RE = re.compile(r"\bon[a-zA-Z]+\s*=", re.IGNORECASE)
_DANGEROUS_SCHEME_TEXT_RE = re.compile(
    r"(javascript|data|vbscript)\s*:", re.IGNORECASE
)
_SQL_META_RE = re.compile(
    r"['\";]|--|/\*|\bunion\b|\bor\s+1\s*=\s*1\b", re.IGNORECASE
)
_SHELL_META_RE = re.compile(r"[;&|`<>]|\$\(|\$\{")

_HTML_URL_ATTR_RE = re.compile(
    r"""(?:src|href)\s*=\s*"([^"]*)"|(?:src|href)\s*=\s*'([^']*)'""",
    re.IGNORECASE,
)
_MD_URL_RE = re.compile(r"\]\(\s*([^)\s]+)")


def extract_urls(channel: str, output: str):
    if channel == "html":
        urls = []
        for m in _HTML_URL_ATTR_RE.finditer(output):
            urls.append(m.group(1) if m.group(1) is not None else m.group(2))
        return urls
    if channel == "markdown":
        return _MD_URL_RE.findall(output)
    if channel == "url":
        return [output.strip()]
    return []


def _resolve_scheme_and_host(raw_url: str):
    """Returns (scheme_or_None, hostname_or_None, is_absolute: bool)."""
    u = raw_url.strip()
    if u.startswith("//"):
        parts = urlsplit("https:" + u)
        return parts.scheme, parts.hostname, True
    parts = urlsplit(u)
    if parts.scheme:  # e.g. "https://...", "javascript:...", "ftp://..."
        return parts.scheme, parts.hostname, True
    # no scheme, no leading "//" -> relative reference, not absolute
    return None, None, False


def check_dangerous_scheme(output: str, urls) -> bool:
    if _DANGEROUS_SCHEME_TEXT_RE.search(output):
        return True
    for raw in urls:
        scheme, _host, is_abs = _resolve_scheme_and_host(raw)
        if is_abs and scheme and scheme.lower() not in ("http", "https"):
            return True
    return False


def check_external_exfil(urls) -> bool:
    for raw in urls:
        scheme, host, is_abs = _resolve_scheme_and_host(raw)
        if not is_abs:
            continue
        if not host or host.lower() not in ALLOWED_HOSTS:
            return True
    return False


# ---------------------------------------------------------------------------
# Channel rule engines — return a failing reason string, or None if it passes
# ---------------------------------------------------------------------------

def check_html(output: str):
    if _SCRIPT_TAG_RE.search(output):
        return "SCRIPT_TAG"
    if _EVENT_HANDLER_RE.search(output):
        return "EVENT_HANDLER"
    urls = extract_urls("html", output)
    if check_dangerous_scheme(output, urls):
        return "DANGEROUS_SCHEME"
    if check_external_exfil(urls):
        return "EXTERNAL_EXFIL"
    return None


def check_markdown(output: str):
    urls = extract_urls("markdown", output)
    if check_dangerous_scheme(output, urls):
        return "DANGEROUS_SCHEME"
    if check_external_exfil(urls):
        return "EXTERNAL_EXFIL"
    return None


def check_url(output: str):
    urls = extract_urls("url", output)
    if check_dangerous_scheme(output, urls):
        return "DANGEROUS_SCHEME"
    if check_external_exfil(urls):
        return "EXTERNAL_EXFIL"
    return None


def check_sql(output: str):
    if _SQL_META_RE.search(output):
        return "SQL_METACHAR"
    return None


def check_shell(output: str):
    if _SHELL_META_RE.search(output):
        return "SHELL_METACHAR"
    return None


_CHANNEL_CHECKERS = {
    "html": check_html,
    "markdown": check_markdown,
    "url": check_url,
    "sql": check_sql,
    "shell": check_shell,
}


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@app.post("/sanitize-output")
async def sanitize_output(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"safe": False, "reason": "INVALID_SCHEMA"})

    if not isinstance(body, dict):
        return JSONResponse({"safe": False, "reason": "INVALID_SCHEMA"})

    channel = body.get("channel")
    output = body.get("output")

    if (
        channel not in VALID_CHANNELS
        or not isinstance(output, str)
        or len(output) > MAX_LEN
    ):
        return JSONResponse({"safe": False, "reason": "INVALID_SCHEMA"})

    checker = _CHANNEL_CHECKERS[channel]

    # Rule 2: ENCODED_PAYLOAD pre-check
    decoded = decode_once(output)
    if decoded != output:
        if checker(decoded) is not None:
            return JSONResponse({"safe": False, "reason": "ENCODED_PAYLOAD"})

    # Rule 3: channel rules on the ORIGINAL output
    reason = checker(output)
    if reason is not None:
        return JSONResponse({"safe": False, "reason": reason})

    return JSONResponse({"safe": True, "reason": "SAFE"})
