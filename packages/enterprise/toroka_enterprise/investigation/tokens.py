"""Privacy-preserving, installation-scoped entity correlation tokens."""
from __future__ import annotations

import hashlib
import hmac
import re
import unicodedata
from uuid import UUID


def normalize_identifier_by_kind(entity_kind: str, raw_identifier: str) -> str:
    """Normalizes raw identifier according to entity domain rules."""
    cleaned = unicodedata.normalize("NFKC", raw_identifier).strip()
    if not cleaned:
        raise ValueError("identifier cannot be empty")

    kind = entity_kind.lower()

    if kind in ("phone", "msisdn"):
        digits_only = re.sub(r"[^\d+]", "", cleaned)
        if digits_only.startswith("+"):
            return digits_only
        if digits_only.startswith("0") and len(digits_only) == 10:
            return "+254" + digits_only[1:]
        if digits_only.startswith("254") and len(digits_only) == 12:
            return "+" + digits_only
        if not digits_only.startswith("+"):
            return "+" + digits_only
        return digits_only

    if kind in ("email", "domain"):
        return cleaned.casefold()

    if kind in ("bank_account", "mobile_money_account", "merchant"):
        # Strip internal whitespace, hyphens, and delimiters; uppercase
        return re.sub(r"[\s\-_/]", "", cleaned).upper()

    if kind in ("national_id", "national_identity"):
        return re.sub(r"[\s\-_]", "", cleaned).upper()

    if kind in ("crypto_wallet", "ip_address"):
        return cleaned.lower()

    return cleaned.casefold()


def make_installation_token(
    *,
    key: bytes,
    installation_id: UUID | str,
    entity_kind: str,
    raw_identifier: str,
) -> str:
    """Create a stable HMAC token strictly within one installation.
    
    Tokens never cross institution boundaries and cannot be reversed.
    Cross-bank matching is prohibited without explicit consortium agreement.
    """
    if len(key) < 32:
        raise ValueError("installation correlation key must be at least 256 bits (32 bytes)")

    normalised = normalize_identifier_by_kind(entity_kind, raw_identifier)
    if not normalised:
        raise ValueError("identifier cannot be empty")

    message = "\x00".join(("toroka-enterprise-v1", str(installation_id), entity_kind.lower(), normalised))
    digest = hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"te1:{entity_kind.lower()}:{digest}"
