"""Domain registration facts via RDAP (context only: a new domain is not proof of anything)."""
from __future__ import annotations

from datetime import datetime, timezone

import httpx
from ssi_rules.vocabulary import CoverageStatus

RDAP_BASE = "https://rdap.org/domain/"


def domain_age_days(domain: str, *, transport: httpx.BaseTransport | None = None, timeout: float = 4.0) -> tuple[CoverageStatus, int | None]:
    try:
        with httpx.Client(transport=transport, timeout=timeout, follow_redirects=True, max_redirects=3) as c:
            r = c.get(RDAP_BASE + domain, headers={"Accept": "application/rdap+json"})
        if r.status_code == 404:
            return CoverageStatus.CHECKED, None
        r.raise_for_status()
        for ev in r.json().get("events", []):
            if ev.get("eventAction") == "registration":
                reg = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                return CoverageStatus.CHECKED, max(0, (datetime.now(timezone.utc) - reg).days)
        return CoverageStatus.CHECKED, None
    except Exception:
        return CoverageStatus.COULD_NOT_CHECK, None
