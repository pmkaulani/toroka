from __future__ import annotations

import re
import unicodedata
from urllib.parse import urlsplit

NEA_REGISTRATION_RE = re.compile(r"(?i)\b(?:RA|NA)\s*/\s*\d{4}\s*/\s*\d{1,2}\s*/\s*\d{1,4}\b")
GENERIC_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "yahoo.co.uk", "outlook.com", "hotmail.com",
    "live.com", "icloud.com", "proton.me", "protonmail.com",
}
SOCIAL_HOSTS = {
    "instagram.com": "instagram", "tiktok.com": "tiktok", "facebook.com": "facebook",
    "x.com": "x", "twitter.com": "x", "linkedin.com": "linkedin",
}


def normalize_name(value: str | None) -> str:
    value = unicodedata.normalize("NFKD", str(value or "")).encode("ascii", "ignore").decode("ascii").casefold()
    value = re.sub(r"\b(private|limited|ltd|plc|company|co|incorporated|inc)\b", " ", value)
    return " ".join(re.sub(r"[^a-z0-9]+", " ", value).split())


def normalize_registration_number(value: str | None) -> str:
    return re.sub(r"[^A-Z0-9/]", "", str(value or "").upper())


def normalize_domain(value: str | None) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = urlsplit(raw if "://" in raw else "https://" + raw)
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host or host.startswith("[") or "/" in host or " " in host:
            return None
        host = host.encode("idna").decode("ascii")
        if host.startswith("www."):
            host = host[4:]
        if len(host) > 253 or "." not in host:
            return None
        labels = host.split(".")
        if any(not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels):
            return None
        return host
    except Exception:
        return None


def email_domain(value: str | None) -> str | None:
    raw = str(value or "").strip().casefold()
    if "@" not in raw:
        return None
    domain = raw.rsplit("@", 1)[-1].strip().rstrip(".,;>")
    return normalize_domain(domain)


def normalize_social_profile(value: str | None) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = urlsplit(raw if "://" in raw else "https://" + raw)
        host = (parsed.hostname or "").lower().removeprefix("www.")
        platform = next((p for suffix, p in SOCIAL_HOSTS.items() if host == suffix or host.endswith("." + suffix)), None)
        if not platform:
            return None
        parts = [p for p in parsed.path.split("/") if p]
        if not parts:
            return None
        handle = parts[0].lstrip("@").casefold()
        if handle in {"p", "reel", "reels", "stories", "share", "watch", "company", "in"}:
            return None
        if not re.fullmatch(r"[a-z0-9._-]{2,64}", handle):
            return None
        return f"{platform}:{handle}"
    except Exception:
        return None


def extract_claims(text: str) -> dict:
    text = str(text or "")[:50000]
    nea_numbers = list(dict.fromkeys(normalize_registration_number(x) for x in NEA_REGISTRATION_RE.findall(text)))
    reg_matches = re.findall(r"(?i)\b(?:BRS|company|business|registration)\s*(?:registration\s*)?(?:no\.?|number|#)\s*[:\-]?\s*([A-Z0-9][A-Z0-9/\-]{3,39})", text)
    brs_numbers = list(dict.fromkeys(normalize_registration_number(x) for x in reg_matches if normalize_registration_number(x)))
    domains: list[str] = []
    emails: list[str] = []
    socials: list[str] = []
    for url in re.findall(r"(?i)https?://[^\s<>\"']+|(?<![\w@])(?:www\.)?[a-z0-9.-]+\.(?:co\.ke|or\.ke|go\.ke|com|org|net|io|app|online|shop)(?:/[^\s<>\"']*)?", text):
        url = url.rstrip(".,;!?)]")
        social = normalize_social_profile(url)
        if social:
            socials.append(social)
        domain = normalize_domain(url)
        if domain and not any(domain == d or domain.endswith("." + d) for d in SOCIAL_HOSTS):
            domains.append(domain)
    for email in re.findall(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", text):
        emails.append(email.casefold())
    return {
        "nea_registration_numbers": nea_numbers[:5],
        "brs_registration_numbers": brs_numbers[:5],
        "domains": list(dict.fromkeys(domains))[:5],
        "emails": list(dict.fromkeys(emails))[:5],
        "social_profiles": list(dict.fromkeys(socials))[:5],
    }
