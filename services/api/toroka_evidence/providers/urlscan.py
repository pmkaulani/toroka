from __future__ import annotations
import os
from datetime import datetime, timezone
from urllib.parse import quote
from ..models import Evidence, InvestigationRequest
from ..normalize import investigation_domain
from .http import get_json


class UrlscanProvider:
    name = "urlscan.io"
    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.getenv("URLSCAN_API_KEY")
        self.is_configured = True  # unauthenticated search has limited quota

    def is_applicable(self, request: InvestigationRequest) -> bool:
        return investigation_domain(request.target, request.claimed_website) is not None

    def investigate(self, request: InvestigationRequest) -> list[Evidence]:
        domain = investigation_domain(request.target, request.claimed_website)
        if not domain:
            return []
        headers = {"api-key": self.api_key} if self.api_key else {}
        # Search existing scans only. Never publicly submit a user's private/tokenized URL implicitly.
        result = get_json(f"https://urlscan.io/api/v1/search/?q={quote('domain:' + domain)}&size=10", headers)
        evidence: list[Evidence] = []
        for hit in result.get("results", [])[:10]:
            verdicts = hit.get("verdicts", {}).get("overall", {})
            if not verdicts.get("malicious") and not verdicts.get("score", 0):
                continue
            page = hit.get("page", {})
            task = hit.get("task", {})
            scan_id = hit.get("_id")
            try:
                scan_time = datetime.fromisoformat(str(task.get("time", "")).replace("Z", "+00:00"))
                if scan_time.tzinfo is None:
                    scan_time = scan_time.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                scan_time = datetime.now(timezone.utc)
            evidence.append(Evidence(
                source=self.name, source_group="urlscan", category="website_behavior", polarity="risk",
                summary=f"An existing urlscan analysis marked a page on {domain} as potentially malicious.",
                why_it_matters="A previous browser-based scan reported suspicious page behaviour or phishing indicators on this domain; the scan date and exact page must be checked.",
                strength=4 if verdicts.get("malicious") else 2, reliability=0.78, confidence=0.72,
                subject=domain, source_url=f"https://urlscan.io/result/{scan_id}/" if scan_id else "https://urlscan.io/",
                observed_at=scan_time, verified=bool(verdicts.get("malicious")),
                limitations=["A historical scan may not describe the current site state.", "A URL scan cannot establish whether an Instagram/TikTok shop fulfils orders."],
                metadata={"scan_id": scan_id, "scan_time": scan_time.isoformat(), "urlscan_score": verdicts.get("score"), "page_domain": page.get("domain")}
            ))
        if not evidence:
            evidence.append(Evidence(
                source=self.name, source_group="urlscan", category="website_behavior", polarity="context",
                summary=f"No matching malicious existing urlscan result was returned for {domain}.",
                why_it_matters="This means the search did not return a matching malicious scan; it does not mean a fresh scan was clean or that the merchant fulfils orders.",
                strength=1, reliability=0.65, confidence=0.55, subject=domain,
                source_url=f"https://urlscan.io/search/#{quote('domain:' + domain)}",
                limitations=["This is not a fresh scan and does not prove the domain is safe.", "Search access and historical coverage depend on account/quota."],
            ))
        return evidence
