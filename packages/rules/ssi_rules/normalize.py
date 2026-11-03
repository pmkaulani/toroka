"""Pure normalisation helpers: Kenyan phone numbers, URLs, amounts, payment ids.

No network I/O lives here. Fetching is a separate, isolated worker concern; this
module only parses and offers `is_fetch_safe` as groundwork for that worker.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

# --- phones -----------------------------------------------------------------
_PHONE_RE = re.compile(r"(?<![\w+])(?:\+?254|0)[\s\-]?([17]\d{2})[\s\-]?(\d{3})[\s\-]?(\d{3})(?!\d)")


@dataclass(frozen=True)
class Found:
    raw: str
    normalized: str
    start: int
    end: int


def normalize_ke_phone(raw: str) -> str | None:
    """Return +254XXXXXXXXX for a plausible Kenyan mobile number, else None.

    Conservative: only 9-digit national numbers starting 7 or 1 are accepted.
    Short codes (333, 456) and landlines are not phones here.
    """
    s = re.sub(r"[^\d+]", "", raw)
    if s.startswith("+254"):
        nsn = s[4:]
    elif s.startswith("254"):
        nsn = s[3:]
    elif s.startswith("0"):
        nsn = s[1:]
    else:
        return None
    if len(nsn) == 9 and nsn.isdigit() and nsn[0] in "17":
        return "+254" + nsn
    return None


def extract_phones(text: str) -> list[Found]:
    out = []
    for m in _PHONE_RE.finditer(text):
        n = normalize_ke_phone(m.group(0))
        if n:
            out.append(Found(m.group(0), n, m.start(), m.end()))
    return out


def mask_phone(normalized: str) -> str:
    """+254722000000 -> +2547••••000 (display_masked in the blueprint's schema)."""
    return normalized[:5] + "••••" + normalized[-3:] if len(normalized) >= 9 else "••••"


# --- amounts and payment destinations ---------------------------------------
_AMOUNT_RE = re.compile(r"(?i)\b(?:ksh?s?|kes)\.?\s?(\d[\d,]*(?:\.\d+)?)")
_PAYBILL_RE = re.compile(r"(?i)\b(pay\s?bill|till)(?:\s*(?:no|number|#))?\.?\s*[:\-]?\s*(\d{5,7})\b")


def extract_amounts(text: str) -> list[Found]:
    return [Found(m.group(0), m.group(1).replace(",", ""), m.start(), m.end()) for m in _AMOUNT_RE.finditer(text)]


def extract_payment_ids(text: str) -> list[Found]:
    out = []
    for m in _PAYBILL_RE.finditer(text):
        kind = "paybill" if "bill" in m.group(1).lower() else "till"
        out.append(Found(m.group(0), f"{kind}:{m.group(2)}", m.start(), m.end()))
    return out


# --- urls -------------------------------------------------------------------
_TLDS = (r"(?:co\.ke|go\.ke|or\.ke|ac\.ke|ne\.ke|sc\.ke|com|net|org|info|biz|xyz|top|click|link|site|online|app|me|ly|gl|"
         r"io|cc|tk|ml|cf|ga|gq|shop|store|live|co|ke)")
_URL_RE = re.compile(
    r"(?<![@\w.\-/])(?:(?:https?://|www\.)[^\s<>\"'()]+|(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+" + _TLDS
    + r"(?![a-z0-9\-])(?:/[^\s<>\"'()]*)?)",
    re.I,
)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "cutt.ly", "rb.gy", "is.gd", "goo.gl", "ow.ly", "shorturl.at", "tiny.cc", "buff.ly"}
_SECOND_LEVEL_KE = {"co", "go", "or", "ac", "ne", "sc", "me"}


@dataclass(frozen=True)
class ParsedUrl:
    original: str
    scheme: str
    host: str
    registered_domain: str
    is_ip: bool
    has_userinfo: bool
    is_punycode: bool
    is_shortener: bool
    start: int = 0
    end: int = 0


def registered_domain(host: str) -> str:
    """Approximate registrable domain without a public-suffix list.

    Handles Kenyan second-level suffixes (co.ke, go.ke, ...); everything else is
    the last two labels. Replace with a PSL-backed library before relying on it.
    """
    labels = host.split(".")
    if len(labels) >= 3 and labels[-1] == "ke" and labels[-2] in _SECOND_LEVEL_KE:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def parse_url(raw: str, start: int = 0, end: int = 0) -> ParsedUrl | None:
    candidate = raw if re.match(r"(?i)^[a-z][a-z0-9+.\-]*://", raw) else "http://" + raw
    try:
        parts = urlsplit(candidate)
        host = (parts.hostname or "").rstrip(".").lower()
    except ValueError:
        return None
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    reg = host if is_ip else registered_domain(host)
    return ParsedUrl(raw, parts.scheme.lower(), host, reg, is_ip, "@" in (parts.netloc or ""),
                     any(l.startswith("xn--") for l in host.split(".")), reg in SHORTENERS or host in SHORTENERS, start, end)


def extract_urls(text: str) -> list[ParsedUrl]:
    out = []
    for m in _URL_RE.finditer(text):
        raw = m.group(0).rstrip(".,;:!?")
        p = parse_url(raw, m.start(), m.start() + len(raw))
        if p:
            out.append(p)
    return out


def is_fetch_safe(url: str) -> tuple[bool, str]:
    """Groundwork for the isolated URL fetcher (OWASP SSRF guidance).

    Literal checks only. The worker must ALSO resolve DNS, re-check every resolved
    address, pin it for the connection (DNS rebinding) and re-validate redirects.
    """
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").rstrip(".").lower()
        port = parts.port
    except ValueError:
        return False, "unparseable url"
    if parts.scheme not in ("http", "https"):
        return False, "unsupported scheme"
    if not host:
        return False, "no host"
    if parts.username or parts.password:
        return False, "credentials in url"
    if port not in (None, 80, 443):
        return False, "unusual port"
    if host == "localhost" or host.endswith((".local", ".internal", ".localhost")):
        return False, "local hostname"
    if all(re.fullmatch(r"0x[0-9a-f]+|\d+", label) for label in host.split(".")):
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False, "numeric host (ambiguous encoding)"
    else:
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            return True, "ok (hostname; resolve and re-check in the worker)"
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    if not ip.is_global:
        return False, "non-public address"
    return True, "ok"
