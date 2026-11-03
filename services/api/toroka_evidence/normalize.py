from __future__ import annotations
from urllib.parse import urlsplit
from ipaddress import ip_address
import re

SOCIAL_PLATFORM_HOSTS = {
    "instagram.com", "facebook.com", "tiktok.com", "x.com", "twitter.com",
    "whatsapp.com", "wa.me", "youtube.com", "youtu.be", "linkedin.com",
}


def normalize_domain(value: str) -> str | None:
    """Return a canonical public hostname; never fetch the supplied URL."""
    raw = (value or "").strip()
    if not raw:
        return None
    candidate = raw if "://" in raw else f"https://{raw}"
    try:
        parts = urlsplit(candidate)
        if parts.scheme.lower() not in {"http", "https"}:
            return None
        host = (parts.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
        # Accessing .port validates malformed/out-of-range ports.
        _ = parts.port
    except (ValueError, UnicodeError):
        return None
    if not host or len(host) > 253 or ".." in host:
        return None
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        return None
    try:
        # Provider lookups are domain-reputation checks, not arbitrary IP probes.
        address = ip_address(host)
        if not address.is_global:
            return None
        return None
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) < 2 or any(
        not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
        or not re.fullmatch(r"[a-z0-9-]+", label)
        for label in labels
    ):
        return None
    return host


def investigation_domain(target: str, claimed_website: str | None = None) -> str | None:
    """Prefer the seller's own website and never scan a social network as the shop domain."""
    candidate = claimed_website or target
    host = normalize_domain(candidate)
    if not host:
        return None
    if any(host == p or host.endswith("." + p) for p in SOCIAL_PLATFORM_HOSTS):
        return None
    return host


def normalize_phone(value: str | None) -> str | None:
    if not value:
        return None
    digits = re.sub(r"\D", "", value)
    if digits.startswith("0") and len(digits) == 10:
        return "+254" + digits[1:]
    if digits.startswith("254") and len(digits) in {12, 13}:
        return "+" + digits
    if digits.startswith("7") and len(digits) == 9:
        return "+254" + digits
    return "+" + digits if len(digits) >= 9 else None
