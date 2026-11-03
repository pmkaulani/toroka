from __future__ import annotations
import hashlib, ipaddress, json, re
from datetime import datetime, timezone
from urllib.parse import urlsplit
from .models import Indicator

_PATTERN = re.compile(r"\[\s*(domain-name:value|url:value|ipv4-addr:value|file:hashes\.'SHA-256')\s*=\s*'([^']+)'\s*\]", re.I)
_SENSITIVE_PATH = re.compile(r"(?i)(token|session|reset|auth|invite|otp|key|code)[=/_-]")


def normalize_indicator(kind: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        raise ValueError("indicator value is missing or too long")
    kind = kind.lower().strip()
    raw = value.strip()
    if kind == "domain":
        candidate = raw if "://" in raw else "https://" + raw
        parts = urlsplit(candidate)
        if not parts.hostname or parts.username or parts.password:
            raise ValueError("invalid domain indicator")
        host = parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        if "." not in host or len(host) > 253 or any(not p or len(p) > 63 for p in host.split(".")):
            raise ValueError("invalid domain indicator")
        if host in {"localhost", "127.0.0.1"} or host.endswith((".local", ".internal", ".test", ".invalid")):
            raise ValueError("non-public domain indicator")
        try: ipaddress.ip_address(host)
        except ValueError: pass
        else: raise ValueError("domain indicator must be a DNS hostname, not an IP literal")
        return host
    if kind == "url":
        parts = urlsplit(raw)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
            raise ValueError("invalid URL indicator")
        host = parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        if host in {"localhost", "127.0.0.1"} or host.endswith((".local", ".internal", ".test", ".invalid")):
            raise ValueError("non-public URL indicator")
        path = parts.path or "/"
        if _SENSITIVE_PATH.search(path):
            path = "/"
        return f"{parts.scheme.lower()}://{host}{path[:256]}"
    if kind == "ipv4":
        address = ipaddress.ip_address(raw)
        if address.version != 4 or not address.is_global:
            raise ValueError("indicator must be a public IPv4 address")
        return str(address)
    if kind == "sha256":
        digest = raw.lower()
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError("SHA-256 indicator must contain 64 hex characters")
        return digest
    raise ValueError(f"unsupported indicator type: {kind}")


def parse_stix_bundle(payload: bytes | str, *, source_id: str, max_objects: int = 100_000) -> tuple[list[Indicator], list[str]]:
    """Parse a safe, explicit STIX 2.1 indicator subset. Unsupported patterns are reported."""
    if isinstance(payload, bytes):
        if len(payload) > 50_000_000:
            raise ValueError("STIX document exceeds parser limit")
        payload = payload.decode("utf-8", errors="strict")
    if len(payload.encode("utf-8")) > 50_000_000:
        raise ValueError("STIX document exceeds parser limit")
    doc = json.loads(payload)
    if not isinstance(doc, dict) or doc.get("type") != "bundle" or not isinstance(doc.get("objects"), list):
        raise ValueError("expected a STIX bundle with an objects array")
    objects = doc["objects"]
    if len(objects) > max_objects:
        raise ValueError("STIX object count exceeds limit")
    indicators: list[Indicator] = []
    warnings: list[str] = []
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        if obj.get("revoked") is True:
            continue
        valid_until = obj.get("valid_until")
        if valid_until:
            try:
                dt = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if dt <= datetime.now(timezone.utc):
                    continue
            except Exception:
                warnings.append("indicator with malformed valid_until skipped")
                continue
        pattern = obj.get("pattern", "")
        if not isinstance(pattern, str) or len(pattern) > 4096:
            warnings.append("indicator with missing/oversized pattern skipped")
            continue
        matches = list(_PATTERN.finditer(pattern))
        if len(matches) != 1 or pattern.strip() != matches[0].group(0) or " AND " in pattern.upper() or " OR " in pattern.upper():
            warnings.append("complex or unsupported STIX pattern skipped")
            continue
        field, raw_value = matches[0].groups()
        kind = {
            "domain-name:value": "domain",
            "url:value": "url",
            "ipv4-addr:value": "ipv4",
            "file:hashes.'sha-256'": "sha256",
        }[field.lower()]
        try:
            value = normalize_indicator(kind, raw_value)
        except Exception:
            warnings.append("invalid indicator value skipped")
            continue
        confidence = obj.get("confidence", 70)
        try:
            confidence = max(0.0, min(1.0, float(confidence) / 100.0 if float(confidence) > 1 else float(confidence)))
        except Exception:
            confidence = 0.7
        labels = tuple(str(x)[:64] for x in obj.get("labels", [])[:10] if isinstance(x, str)) if isinstance(obj.get("labels", []), list) else ()
        indicators.append(Indicator(kind, value, confidence, labels, valid_until if isinstance(valid_until, str) else None))
    # Deduplicate stable records
    unique = {(i.indicator_type, i.value): i for i in indicators}
    return list(unique.values()), warnings


def snapshot_digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()
