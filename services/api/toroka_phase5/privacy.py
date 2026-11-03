from __future__ import annotations

import hashlib
import hmac
import re
from urllib.parse import urlsplit

_PHONE_RE = re.compile(r"(?<!\w)(?:\+?254\s?7\d{2}[\s-]?\d{3}[\s-]?\d{3}|0?7\d{2}[\s-]?\d{3}[\s-]?\d{3})(?!\w)")
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
_LONG_NUMBER_RE = re.compile(r"(?<!\w)\d{6,}(?!\w)")
_SECRET_RE = re.compile(r"\b(?:otp|one[- ]time password|pin|mpesa pin|m-pesa pin|password|passcode)\s*[:#-]?\s*[A-Z0-9-]{3,}\b", re.I)
_URL_RE = re.compile(r"https?://[^\s<>\]\[()]+", re.I)
_NAME_FIELD_RE = re.compile(r"(?i)(?:sent to|paid to|recipient|business name|account name)\s*[:=-]\s*[^,\r\n.]{2,48}")
_TRANSACTION_RE = re.compile(r"(?i)(?:transaction\s*(?:id|code|reference)?|receipt\s*(?:no|number)?|ref(?:erence)?)\s*[:#=-]?\s*[A-Z0-9]{8,12}\b")


def normalize_ke_phone(raw: str) -> str | None:
    digits = re.sub(r"\D", "", raw)
    if len(digits) == 12 and digits.startswith("2547"):
        return "+" + digits
    if len(digits) == 10 and digits.startswith("07"):
        return "+254" + digits[1:]
    if len(digits) == 9 and digits.startswith("7"):
        return "+254" + digits
    return None


def mask_phone(raw: str) -> str:
    normalized = normalize_ke_phone(raw)
    if not normalized:
        return "[phone redacted]"
    return normalized[:6] + "•••" + normalized[-2:]


def safe_excerpt(text: str, *, limit: int = 220) -> str:
    """Return a short display excerpt with secrets and personal identifiers removed."""
    excerpt = _SECRET_RE.sub("[credential redacted]", text)
    excerpt = _NAME_FIELD_RE.sub("recipient: [name redacted]", excerpt)
    excerpt = _TRANSACTION_RE.sub("transaction reference: [redacted]", excerpt)
    excerpt = _EMAIL_RE.sub("[email redacted]", excerpt)
    excerpt = _PHONE_RE.sub(lambda m: mask_phone(m.group(0)), excerpt)
    excerpt = _LONG_NUMBER_RE.sub("[number redacted]", excerpt)

    def safe_url(match: re.Match[str]) -> str:
        raw = match.group(0).rstrip(".,;!?")
        try:
            host = urlsplit(raw).hostname or ""
            return host.lower() if host else "[link redacted]"
        except ValueError:
            return "[link redacted]"

    excerpt = _URL_RE.sub(safe_url, excerpt)
    excerpt = re.sub(r"\s+", " ", excerpt).strip()
    return excerpt[:limit]


def keyed_fingerprint(value: str, *, secret: bytes, namespace: str) -> str:
    if len(secret) < 32:
        raise ValueError("secret must contain at least 32 bytes")
    if not namespace or not re.fullmatch(r"[a-z0-9:_-]{1,48}", namespace):
        raise ValueError("namespace must be a short lowercase identifier")
    normalized = value.strip().casefold()
    digest = hmac.new(secret, f"toroka-phase5:{namespace}:{normalized}".encode(), hashlib.sha256).hexdigest()
    return digest
