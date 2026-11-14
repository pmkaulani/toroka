from __future__ import annotations
from .models import Evidence, InvestigationRequest, InvestigationResult, LocationMatch
from .scoring import assess
from .profile import EngineProfile, SHOPPER_PROFILE
from .provider_protocols import Provider, LocationProvider


class EvidenceEngine:
    def __init__(self, providers: list[Provider] | None = None, location_providers: list[LocationProvider] | None = None,
                 profile: EngineProfile = SHOPPER_PROFILE):
        self.providers = providers or []
        self.location_providers = location_providers or []
        self.profile = profile

    def investigate(self, request: InvestigationRequest) -> InvestigationResult:
        evidence: list[Evidence] = []
        locations: list[LocationMatch] = []
        completed: list[str] = []
        unavailable: list[str] = []
        skipped: list[str] = []
        limitations: list[str] = list(self.profile.base_limitations)
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

        verdict, risk_index, confidence, conclusion = assess(evidence, policy=self.profile.scoring)
        risks = [e for e in evidence if e.polarity == "risk"]
        supports = [e for e in evidence if e.polarity == "support"]
        context = [e for e in evidence if e.polarity == "context"]

        actions = self.profile.action_builder(verdict, evidence, locations)

        return InvestigationResult(
            target=request.target, verdict=verdict, risk_index=risk_index, confidence=confidence,
            conclusion=conclusion, risk_evidence=risks, supporting_evidence=supports,
            context_evidence=context, locations=locations, completed_checks=completed,
            unavailable_checks=unavailable, skipped_checks=skipped,
            recommended_actions=actions, limitations=limitations,
            risk_index_note=self.profile.risk_index_note, confidence_note=self.profile.confidence_note,
        )
