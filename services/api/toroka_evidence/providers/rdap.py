from __future__ import annotations
from datetime import datetime, timezone
from urllib.parse import quote
from ..models import Evidence, InvestigationRequest
from ..normalize import investigation_domain
from .http import get_json


class RdapProvider:
    name = "ICANN RDAP"
    is_configured = True
    def is_applicable(self, request: InvestigationRequest) -> bool:
        return investigation_domain(request.target, request.claimed_website) is not None

    def investigate(self, request: InvestigationRequest) -> list[Evidence]:
        domain = investigation_domain(request.target, request.claimed_website)
        if not domain:
            return []
        data = get_json(f"https://rdap.org/domain/{quote(domain)}")
        created = next((e.get("eventDate") for e in data.get("events", []) if e.get("eventAction") == "registration"), None)
        if not created:
            return [Evidence(source=self.name, source_group="rdap", category="domain_registration", polarity="context", summary=f"RDAP did not provide a domain registration date for {domain}.", why_it_matters="Without a registration date, Toroka cannot use domain age as context; the missing field is not a risk or trust signal.", strength=1, reliability=0.8, confidence=0.4, subject=domain, source_url=f"https://lookup.icann.org/en/lookup?name={quote(domain)}", limitations=["Registration dates may be unavailable or redacted."])]
        try:
            created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
            age_days = max(0, (datetime.now(timezone.utc) - created_dt).days)
        except (ValueError, TypeError):
            return []
        # A young domain is weak context only; scammers and legitimate small shops both use new domains.
        return [Evidence(source=self.name, source_group="rdap", category="domain_registration", polarity="context", summary=f"The domain {domain} was registered approximately {age_days} days ago.", why_it_matters="Domain age can help identify very new web infrastructure, but it is only weak context because legitimate small shops also launch new domains.", strength=1, reliability=0.9, confidence=0.95, subject=domain, source_url=f"https://lookup.icann.org/en/lookup?name={quote(domain)}", limitations=["A new domain is not proof of fraud; a long-established domain is not proof of trustworthy sales.", "RDAP data describes the domain registration, not the business owner."], metadata={"registered_at": created_dt.isoformat(), "age_days": age_days})]
