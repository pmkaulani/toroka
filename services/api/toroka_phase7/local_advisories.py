from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import re
from urllib.parse import urlsplit

OFFICIAL_KE_CIRT_HOSTS={"ke-cirt.go.ke","www.ke-cirt.go.ke","ca.go.ke","www.ca.go.ke"}

@dataclass(frozen=True, slots=True)
class CuratedAdvisory:
    advisory_id: str
    authority: str
    title: str
    source_url: str
    published_at: str
    retrieved_at: str
    reviewed_by: str
    summary: str
    source_type: str = "official_public_advisory"
    limitations: tuple[str,...] = (
        "This is national cyber-threat context, not proof that a specific seller or person is involved.",
        "Quarterly statistics and general advisories are not automatically converted into domain/phone indicators.",
        "The source and publication date should be rechecked before presenting this information as current.",
    )
    def to_dict(self): return asdict(self)


def _iso(value):
    if isinstance(value,datetime): d=value
    else: d=datetime.fromisoformat(str(value).replace("Z","+00:00"))
    if d.tzinfo is None: raise ValueError("timestamp must include a timezone")
    return d.astimezone(timezone.utc).isoformat()


def curate_ke_cirt_advisory(*, title: str, source_url: str, published_at: str,
                            reviewed_by: str, summary: str, retrieved_at=None) -> CuratedAdvisory:
    """Create an operator-reviewed citation for an official KE-CIRT/CA page.

    This function does not scrape the site, infer IOCs or turn national trend reporting
    into a verdict about an individual merchant.
    """
    if not isinstance(title,str) or not title.strip() or len(title)>240: raise ValueError("title must be 1-240 characters")
    if not isinstance(reviewed_by,str) or not re.fullmatch(r"[A-Za-z0-9._-]{3,80}",reviewed_by): raise ValueError("reviewed_by must be an opaque staff identifier")
    parts=urlsplit(source_url)
    if parts.scheme!="https" or not parts.hostname or parts.username or parts.password: raise ValueError("source URL must be HTTPS without credentials")
    host=parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    if host not in OFFICIAL_KE_CIRT_HOSTS: raise ValueError("source URL must use an official KE-CIRT/Communications Authority host")
    pub=_iso(published_at); retrieved=_iso(retrieved_at or datetime.now(timezone.utc))
    if not isinstance(summary,str) or len(summary)>1500: raise ValueError("summary must be at most 1500 characters")
    # Keep the human-authored note brief and scrub obvious direct identifiers.
    clean=re.sub(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}","[email]",summary,flags=re.I)
    clean=re.sub(r"(?:\+?254|0)?7\d{8}","[phone]",clean)
    clean=re.sub(r"\b\d{7,}\b","[identifier]",clean)
    advisory_id=__import__("hashlib").sha256(f"{host}|{parts.path}|{pub}".encode()).hexdigest()[:20]
    authority="National KE-CIRT/CC" if host.endswith("ke-cirt.go.ke") else "Communications Authority of Kenya"
    safe_path=parts.path or "/"
    if re.search(r"(?i)(token|session|reset|auth|invite|otp|key|code)[=/_-]",safe_path) or any(len(seg)>60 for seg in safe_path.split("/")):
        safe_path="/"
    safe_url=f"https://{host}{safe_path[:300]}"
    return CuratedAdvisory(advisory_id,authority,title.strip(),safe_url,pub,retrieved,reviewed_by,clean[:700])


def kenya_reference_sources() -> list[dict]:
    return [
        {"name":"National KE-CIRT/CC Alerts & Advisories","url":"https://ke-cirt.go.ke/alerts-advisories/","ingestion":"manual_reviewed_citation","automated_indicator_feed":False},
        {"name":"National KE-CIRT/CC Quarterly Cybersecurity Reports","url":"https://ke-cirt.go.ke/quarterly-reports/","ingestion":"manual_reviewed_citation","automated_indicator_feed":False},
        {"name":"Communications Authority Cyber Security","url":"https://ca.go.ke/cyber-security","ingestion":"manual_reviewed_citation","automated_indicator_feed":False},
    ]
