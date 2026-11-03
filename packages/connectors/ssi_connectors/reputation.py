"""Link reputation providers. Licensing matters (blueprint 4.8).

Google Safe Browsing is non-commercial; a revenue-generating product needs Web Risk or another licensed provider.
The Web Risk adapter below follows the documented uris.search shape but has NOT been run against the live API here.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import httpx
from ssi_rules.normalize import parse_url
from ssi_rules.observations import Reputation
from ssi_rules.vocabulary import CoverageStatus

WEBRISK_URL = "https://webrisk.googleapis.com/v1/uris:search"
THREATS = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]


def _now():
    return datetime.now(timezone.utc)


class LocalBlocklist:
    """Entries are exact URLs, hosts or registered domains, each with its own source note (for corroborated, reviewed entries)."""

    def __init__(self, entries: list[dict], source: str = "local-blocklist", licence_note: str = "Own data"):
        self.source, self.licence_note = source, licence_note
        self.hosts = {e["value"].lower(): e.get("threat", "SOCIAL_ENGINEERING") for e in entries if e.get("kind", "host") in ("host", "domain")}
        self.urls = {e["value"]: e.get("threat", "SOCIAL_ENGINEERING") for e in entries if e.get("kind") == "url"}

    def lookup(self, url: str) -> Reputation:
        p = parse_url(url)
        now = _now()
        threats = []
        if url in self.urls:
            threats.append(self.urls[url])
        if p:
            for key in (p.host, p.registered_domain):
                if key in self.hosts:
                    threats.append(self.hosts[key])
        return Reputation(CoverageStatus.CHECKED, self.source, sorted(set(threats)), now.isoformat(), (now + timedelta(hours=6)).isoformat(), self.licence_note)


class WebRiskProvider:
    def __init__(self, api_key: str, transport: httpx.BaseTransport | None = None, timeout: float = 4.0, source: str = "Google Web Risk"):
        self.api_key, self.transport, self.timeout, self.source = api_key, transport, timeout, source
        self._cache: dict[str, tuple[float, Reputation]] = {}

    def lookup(self, url: str) -> Reputation:
        hit = self._cache.get(url)
        if hit and hit[0] > time.monotonic():
            return hit[1]
        params = [("threatTypes", t) for t in THREATS] + [("uri", url), ("key", self.api_key)]
        try:
            with httpx.Client(transport=self.transport, timeout=self.timeout) as c:
                r = c.get(WEBRISK_URL, params=params)
            r.raise_for_status()
            data = r.json()
        except Exception:
            return Reputation(CoverageStatus.COULD_NOT_CHECK, self.source)
        threat = data.get("threat") or {}
        now = _now()
        rep = Reputation(CoverageStatus.CHECKED, self.source, list(threat.get("threatTypes", [])), now.isoformat(),
                         threat.get("expireTime") or (now + timedelta(minutes=30)).isoformat(), "Licensed provider; results are not exhaustive")
        self._cache[url] = (time.monotonic() + 600, rep)
        return rep


def combine(providers: list, url: str) -> Reputation | None:
    """None when nothing is configured (the assessment then says not_checked)."""
    if not providers:
        return None
    results = [p.lookup(url) for p in providers]
    ok = [r for r in results if r.status == CoverageStatus.CHECKED]
    if not ok:
        return results[0]
    return Reputation(CoverageStatus.CHECKED, " + ".join(r.source for r in ok), sorted({t for r in ok for t in r.threat_types}),
                      min(r.observed_at for r in ok if r.observed_at), min((r.valid_until for r in ok if r.valid_until), default=None))
