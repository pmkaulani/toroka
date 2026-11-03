"""Open-map existence check for a claimed place (Nominatim / OpenStreetMap). Context, never proof.

Nominatim's usage policy requires an identifying User-Agent, at most one request per second and attribution (ODbL).
Not enabled by default.
"""
from __future__ import annotations

import time

import httpx
from ssi_rules.observations import GeocodeObservation
from ssi_rules.vocabulary import CoverageStatus
from datetime import datetime, timezone


class NominatimGeocoder:
    def __init__(self, user_agent: str, transport: httpx.BaseTransport | None = None, base: str = "https://nominatim.openstreetmap.org/search"):
        if not user_agent or "@" not in user_agent and "http" not in user_agent:
            raise ValueError("Nominatim requires a User-Agent that identifies the application and a contact")
        self.ua, self.transport, self.base, self._last = user_agent, transport, base, 0.0

    def lookup(self, place: str) -> GeocodeObservation:
        wait = 1.0 - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()
        try:
            with httpx.Client(transport=self.transport, timeout=5.0) as c:
                r = c.get(self.base, params={"q": place, "format": "jsonv2", "countrycodes": "ke", "limit": 1}, headers={"User-Agent": self.ua})
            r.raise_for_status()
            found = bool(r.json())
            return GeocodeObservation(place, CoverageStatus.CHECKED, found, "OpenStreetMap Nominatim", datetime.now(timezone.utc).isoformat())
        except Exception:
            return GeocodeObservation(place, CoverageStatus.COULD_NOT_CHECK, None, "OpenStreetMap Nominatim")
