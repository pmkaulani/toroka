from __future__ import annotations
import os
from urllib.parse import urlencode, urlsplit, urlunsplit
from ..models import Evidence, InvestigationRequest
from ..normalize import normalize_domain, SOCIAL_PLATFORM_HOSTS


class PhishTankProvider:
    """Check a merchant-controlled URL against PhishTank's verified phishing records."""
    name = "PhishTank"
    def __init__(self, app_key: str | None = None):
        self.app_key = app_key or os.getenv("PHISHTANK_APP_KEY")
        self.is_configured = bool(self.app_key)

    @staticmethod
    def _lookup_url(value: str) -> str | None:
        """Send only the canonical domain root; never disclose path/query tokens."""
        raw = (value or "").strip()
        candidate = raw if "://" in raw else f"https://{raw}"
        try:
            parts = urlsplit(candidate)
            scheme = parts.scheme.lower()
            if scheme not in {"http", "https"}:
                return None
            _ = parts.port
            host = normalize_domain(candidate)
        except ValueError:
            return None
        if not host or any(host == p or host.endswith("." + p) for p in SOCIAL_PLATFORM_HOSTS):
            return None
        # Intentionally query only the origin. A URL path may contain reset tokens,
        # order IDs, invitation codes, or other user-specific secrets.
        return urlunsplit((scheme, host, "/", "", ""))


    def is_applicable(self, request: InvestigationRequest) -> bool:
        return self._lookup_url(request.claimed_website or request.target) is not None

    def investigate(self, request: InvestigationRequest) -> list[Evidence]:
        if not self.app_key:
            return []
        lookup_url = self._lookup_url(request.claimed_website or request.target)
        if not lookup_url or not normalize_domain(lookup_url):
            return []
        payload = urlencode({"url": lookup_url, "format": "json", "app_key": self.app_key}).encode("utf-8")
        # PhishTank accepts form-encoded POST. Use the generic HTTP helper with a mapping-free body.
        from urllib.request import Request, urlopen
        from urllib.error import HTTPError, URLError
        import json
        req = Request("https://checkurl.phishtank.com/checkurl/", data=payload, method="POST", headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": "Toroka/Phase2 evidence-checker"
        })
        try:
            with urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            raise RuntimeError(f"PhishTank returned HTTP {exc.code}") from exc
        except (URLError, TimeoutError, ValueError, UnicodeDecodeError) as exc:
            raise RuntimeError(f"PhishTank lookup failed: {type(exc).__name__}") from exc

        result = data.get("results", {})
        in_db = str(result.get("in_database", "false")).lower() == "true"
        verified = str(result.get("verified", "no")).lower() == "yes"
        valid = str(result.get("valid", "no")).lower() == "yes"
        if in_db and verified and valid:
            return [Evidence(
                source=self.name, source_group="phishtank", category="phishing_report", polarity="risk",
                summary="PhishTank has a community-verified, currently valid phishing record matching the seller domain checked.",
                why_it_matters="A verified, active phishing entry is a strong warning that the checked domain has been associated with phishing; it does not by itself identify the operator of a separate shop profile.",
                strength=5, reliability=0.9, confidence=0.92, subject=lookup_url,
                source_url=result.get("phish_detail_page") or "https://phishtank.org/",
                verified=True,
                limitations=["This record concerns the matched URL, not necessarily the owner of a separate social-media profile.", "The lookup was restricted to the domain root to avoid disclosing user-specific paths, query parameters, or fragments; this may miss a phishing record tied only to a specific path.", "Re-check current validity before making a final decision."],
                metadata={"phish_id": result.get("phish_id"), "verified": verified, "valid": valid, "submission_time": result.get("submission_time")}
            )]
        return [Evidence(
            source=self.name, source_group="phishtank", category="phishing_report", polarity="context",
            summary="No currently verified PhishTank phishing record was returned for the normalized URL.",
            why_it_matters="PhishTank is a phishing database, not a general ecommerce complaint registry; a non-match says nothing conclusive about product delivery or seller honesty.",
            strength=1, reliability=0.85, confidence=0.6, subject=lookup_url,
            source_url="https://phishtank.org/",
            limitations=["No PhishTank match is not proof that the seller or website is legitimate.", "Paths, query parameters, and fragments were deliberately excluded from the lookup; a path-only phishing entry may not be found."],
            metadata={"in_database": in_db, "verified": verified, "valid": valid}
        )]
