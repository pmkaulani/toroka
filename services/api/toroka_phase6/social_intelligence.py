from __future__ import annotations
from datetime import datetime, timezone
from urllib.parse import urlsplit
import re

PLATFORM_HOSTS = {
    "instagram": {"instagram.com", "www.instagram.com"},
    "tiktok": {"tiktok.com", "www.tiktok.com", "m.tiktok.com"},
    "facebook": {"facebook.com", "www.facebook.com", "m.facebook.com"},
}
ALLOWED_COLLECTION_MODES = {"platform_authorized_api", "official_platform_embed", "user_supplied_capture", "merchant_authorized_export"}


def parse_social_profile_url(url: str) -> dict:
    if not isinstance(url, str) or len(url) > 2048:
        raise ValueError("profile URL missing or too long")
    p = urlsplit(url.strip())
    if p.scheme != "https" or p.username or p.password or p.port not in (None, 443):
        raise ValueError("social profile URL must use HTTPS without credentials or a custom port")
    host = (p.hostname or "").lower()
    platform = next((name for name, hosts in PLATFORM_HOSTS.items() if host in hosts), None)
    if not platform:
        raise ValueError("unsupported or non-canonical social platform host")
    parts = [part for part in p.path.split("/") if part]
    if not parts:
        raise ValueError("profile handle missing")
    # Common route prefixes are not profile handles.
    if parts[0].lower() in {"p", "reel", "reels", "stories", "share", "watch", "login"}:
        raise ValueError("URL is a content or utility route, not a profile URL")
    handle = parts[0].lstrip("@").lower()
    if not re.fullmatch(r"[a-z0-9._]{1,64}", handle):
        raise ValueError("invalid public handle")
    canonical = f"https://www.tiktok.com/@{handle}" if platform == "tiktok" else f"https://{platform}.com/{handle}"
    return {"platform": platform, "handle": handle, "canonical_url": canonical}


def inspect_social_observation(observation: dict) -> dict:
    """Accept only authorized APIs, platform embeds, user captures or merchant exports."""
    mode = observation.get("collection_mode")
    if mode not in ALLOWED_COLLECTION_MODES:
        raise ValueError("unsupported collection mode; do not scrape or bypass platform access controls")
    parsed = parse_social_profile_url(observation.get("profile_url", ""))
    if observation.get("platform") and observation["platform"] != parsed["platform"]:
        raise ValueError("platform label does not match profile URL")
    observed_at = observation.get("observed_at")
    if observed_at:
        datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    data = observation.get("public_fields", {})
    if not isinstance(data, dict):
        raise ValueError("public_fields must be an object")
    allowed = {"display_name", "bio", "is_platform_verified", "profile_link", "public_business_email_present", "public_website_host"}
    clean = {}
    limits = {"display_name": 160, "bio": 500, "profile_link": 2048, "public_website_host": 253}
    for key, value in data.items():
        if key not in allowed:
            continue
        if key == "is_platform_verified":
            if isinstance(value, bool):
                clean[key] = value
            continue
        if key == "public_business_email_present":
            if isinstance(value, bool):
                clean[key] = value
            continue
        if isinstance(value, str):
            value = "".join(ch for ch in value if ch.isprintable()).strip()[:limits.get(key, 200)]
            if key == "bio":
                value = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[email redacted]", value)
                value = re.sub(r"(?:\+?254|0)?7\d{8}", "[phone redacted]", value)
                value = value[:limits["bio"]]
            clean[key] = value
    stale = False
    if observed_at:
        dt = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        stale = (datetime.now(timezone.utc) - dt.astimezone(timezone.utc)).total_seconds() > 30 * 86400
    return {**parsed, "collection_mode": mode, "public_fields": clean, "observed_at": observed_at, "stale": stale,
            "source_group": "user_submitted_artifact" if mode in {"user_supplied_capture", "merchant_authorized_export"} else "public_web_observation",
            "limitations": ["A platform verification badge verifies a platform-defined account status, not the seller's fulfilment or payment behaviour.",
                            "Profile content can change after this observation."] + (["Observation is older than 30 days and should be refreshed."] if stale else [])}


def social_observation_findings(record: dict, artifact_ref: str) -> list[dict]:
    data = record.get("public_fields", {})
    findings = [{"category": "social_profile_observed", "severity": "context", "polarity": "context", "confidence": 0.9,
                 "summary": f"Public {record['platform']} profile observed", "explanation": f"Toroka observed @{record['handle']} through {record['collection_mode']}. This records a profile observation; it does not establish who controls the account.",
                 "source_group": record["source_group"], "artifact_ref": artifact_ref}]
    if record.get("stale"):
        findings.append({"category": "social_profile_observation_stale", "severity": "low", "polarity": "context", "confidence": 0.8,
                         "summary": "Social profile observation is stale", "explanation": "The last observation is older than 30 days. Refresh the authorized observation before relying on profile details.",
                         "source_group": record["source_group"], "artifact_ref": artifact_ref})
    if data.get("is_platform_verified") is True:
        findings.append({"category": "social_platform_badge_present", "severity": "context", "polarity": "reassuring", "confidence": 0.8,
                         "summary": "Platform reports a verification badge", "explanation": "The supplied platform-authorized observation reports a verification badge. This does not guarantee product quality, delivery, refunds or payment safety.",
                         "source_group": record["source_group"], "artifact_ref": artifact_ref})
    return findings
