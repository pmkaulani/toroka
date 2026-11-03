from __future__ import annotations
import os
from datetime import datetime, timezone
from urllib.parse import quote
from ..models import Evidence, InvestigationRequest
from ..normalize import investigation_domain
from .http import get_json


class VirusTotalProvider:
    name = "VirusTotal"
    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        # The free Public API is not permitted in commercial products/services.
        # Enable only after a vendor agreement explicitly covers Toroka's product use
        # and the exact downstream display/redistribution of results.
        licensed = os.getenv("TOROKA_VIRUSTOTAL_DISPLAY_LICENSE_CONFIRMED", "").lower() == "true"
        self.is_configured = bool(self.api_key and licensed)

    def is_applicable(self, request: InvestigationRequest) -> bool:
        return investigation_domain(request.target, request.claimed_website) is not None

    def investigate(self, request: InvestigationRequest) -> list[Evidence]:
        domain = investigation_domain(request.target, request.claimed_website)
        if not self.api_key or not domain:
            return []
        data = get_json(f"https://www.virustotal.com/api/v3/domains/{quote(domain)}", {"x-apikey": self.api_key})
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        total = sum(int(v or 0) for v in stats.values() if isinstance(v, (int, float)))
        try:
            observed_at = datetime.fromtimestamp(int(attrs.get("last_analysis_date")), tz=timezone.utc)
        except (TypeError, ValueError, OSError):
            observed_at = datetime.now(timezone.utc)
        if not malicious and not suspicious:
            return [Evidence(
                source=self.name, source_group="virustotal", category="threat_intelligence", polarity="context",
                summary=f"VirusTotal returned no malicious or suspicious detections for {domain} in this report.",
                why_it_matters="This only describes detections in the report at the time of the check; an absence of detections does not confirm a trustworthy seller.",
                strength=1, reliability=0.85, confidence=0.7, subject=domain,
                observed_at=observed_at, source_url=f"https://www.virustotal.com/gui/domain/{domain}",
                limitations=["A clean or empty result is not proof that a seller is legitimate.", "This check concerns the domain, not the seller's delivery or payment behaviour."],
                metadata={"malicious": malicious, "suspicious": suspicious, "engines_reporting": total}
            )]
        return [Evidence(
            source=self.name, source_group="virustotal", category="threat_intelligence", polarity="risk",
            summary=f"VirusTotal reports {malicious} malicious and {suspicious} suspicious engine detections for {domain}.",
            why_it_matters="Multiple security-engine detections are a domain-level warning relevant to visitors opening the shop website; they do not prove who controls a separate social-media account.",
            strength=5 if malicious >= 2 else 3, reliability=0.88, confidence=0.82 if malicious else 0.62,
            subject=domain, observed_at=observed_at,
            source_url=f"https://www.virustotal.com/gui/domain/{domain}",
            verified=malicious >= 2,
            limitations=["Multi-engine detections can include false positives; inspect the underlying vendors and detection dates.", "This is a domain-level signal, not direct proof about a social-media seller."],
            metadata={"malicious": malicious, "suspicious": suspicious, "engines_reporting": total}
        )]
