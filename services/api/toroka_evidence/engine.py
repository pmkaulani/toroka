from __future__ import annotations
from .models import Evidence, InvestigationRequest, InvestigationResult, LocationMatch
from .scoring import assess
from .providers.base import Provider, LocationProvider


class EvidenceEngine:
    def __init__(self, providers: list[Provider] | None = None, location_providers: list[LocationProvider] | None = None):
        self.providers = providers or []
        self.location_providers = location_providers or []

    def investigate(self, request: InvestigationRequest) -> InvestigationResult:
        evidence: list[Evidence] = []
        locations: list[LocationMatch] = []
        completed: list[str] = []
        unavailable: list[str] = []
        skipped: list[str] = []
        limitations: list[str] = [
            "Automated checks evaluate public signals; they cannot guarantee that goods will be delivered or that a payment recipient is honest.",
            "Do not treat missing complaints, a clean threat-feed result, an old domain, or a map pin as proof of legitimacy.",
            "A social-media platform URL is not evidence that the account owner controls a separate website or physical shop."
        ]
        for provider in self.providers:
            if hasattr(provider, "is_applicable") and not provider.is_applicable(request):
                skipped.append(provider.name)
                continue
            if not getattr(provider, "is_configured", True):
                unavailable.append(provider.name)
                continue
            try:
                batch = provider.investigate(request)
                evidence.extend(batch)
                completed.append(provider.name)
            except Exception as exc:  # provider failures must not abort the investigation
                unavailable.append(provider.name)
                limitations.append(f"{provider.name} could not be queried ({type(exc).__name__}); no conclusion was drawn from that missing check.")
        for provider in self.location_providers:
            if hasattr(provider, "is_applicable") and not provider.is_applicable(request):
                skipped.append(provider.name)
                continue
            if not getattr(provider, "is_configured", True):
                unavailable.append(provider.name)
                continue
            try:
                locations.extend(provider.find_locations(request))
                completed.append(provider.name)
            except Exception as exc:
                unavailable.append(provider.name)
                limitations.append(f"{provider.name} location lookup failed ({type(exc).__name__}); no location was treated as verified.")

        verdict, risk_index, confidence, conclusion = assess(evidence)
        risks = [e for e in evidence if e.polarity == "risk"]
        supports = [e for e in evidence if e.polarity == "support"]
        context = [e for e in evidence if e.polarity == "context"]

        actions: list[str] = []
        if verdict in {"high_risk", "suspicious", "mixed_signals", "insufficient_evidence"}:
            actions.extend([
                "Do not pay a personal number or unfamiliar till/paybill solely because the seller sent it; independently verify the recipient and business relationship.",
                "Ask for a live video showing the item, current date, shop identity, and dispatch process; reverse-search product photos independently.",
                "Use a payment method with a dispute path, and avoid deposits or fees to unlock a prize, job, grant, refund, or delivery."
            ])
        if not locations:
            actions.append("No matching physical shop location was verified in the checks completed. Ask the seller for a precise location and independently confirm it before visiting or paying.")
        elif locations:
            actions.append("Treat map results as candidate listings only. Confirm the phone number, website, exact premises, and seller identity independently.")
        if not evidence:
            actions.append("Provide the seller's own website, phone number, payment recipient, or a screenshot of the offer so additional checks can be run.")

        return InvestigationResult(
            target=request.target, verdict=verdict, risk_index=risk_index, confidence=confidence,
            conclusion=conclusion, risk_evidence=risks, supporting_evidence=supports,
            context_evidence=context, locations=locations, completed_checks=completed,
            unavailable_checks=unavailable, skipped_checks=skipped,
            recommended_actions=actions, limitations=limitations
        )
