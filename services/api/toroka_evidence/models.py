from __future__ import annotations
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
import uuid

Polarity = Literal["risk", "support", "context"]
Verdict = Literal["high_risk", "suspicious", "mixed_signals", "lower_observed_risk", "insufficient_evidence"]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class Evidence:
    """A traceable claim from one source; not a free-form model assertion."""
    source: str
    source_group: str
    category: str
    polarity: Polarity
    summary: str
    why_it_matters: str = ""
    strength: int = 2                 # 1 (weak) .. 5 (critical)
    reliability: float = 0.5         # source reliability, 0..1
    confidence: float = 0.5          # confidence in this specific match, 0..1
    subject: str = ""
    source_url: str | None = None
    observed_at: datetime = field(default_factory=utc_now)
    expires_at: datetime | None = None
    verified: bool = False
    limitations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    evidence_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self) -> None:
        if self.polarity not in {"risk", "support", "context"}:
            raise ValueError("polarity must be risk, support, or context")
        if not 1 <= self.strength <= 5:
            raise ValueError("strength must be between 1 and 5")
        for name in ("reliability", "confidence"):
            value = getattr(self, name)
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between 0 and 1")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["observed_at"] = self.observed_at.isoformat()
        data["expires_at"] = self.expires_at.isoformat() if self.expires_at else None
        return data


@dataclass(slots=True)
class LocationMatch:
    name: str
    address: str
    source: str
    source_url: str | None = None
    website_url: str | None = None
    phone: str | None = None
    place_id: str | None = None
    phone_match: bool | None = None
    website_match: bool | None = None
    latitude: float | None = None
    longitude: float | None = None
    business_status: str | None = None
    match_summary: str = ""
    status: str = "third_party_listing_unverified"
    checked_at: datetime = field(default_factory=utc_now)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["checked_at"] = self.checked_at.isoformat()
        return data


@dataclass(slots=True)
class InvestigationRequest:
    target: str
    business_name: str | None = None
    social_handle: str | None = None
    search_location: str | None = None
    claimed_phone: str | None = None
    claimed_payment_identifier: str | None = None
    claimed_payment_name: str | None = None
    claimed_website: str | None = None
    consent_to_submit_url_for_public_scan: bool = False
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class InvestigationResult:
    target: str
    verdict: Verdict
    risk_index: int | None
    confidence: Literal["low", "moderate", "high"]
    conclusion: str
    risk_evidence: list[Evidence] = field(default_factory=list)
    supporting_evidence: list[Evidence] = field(default_factory=list)
    context_evidence: list[Evidence] = field(default_factory=list)
    locations: list[LocationMatch] = field(default_factory=list)
    completed_checks: list[str] = field(default_factory=list)
    unavailable_checks: list[str] = field(default_factory=list)
    skipped_checks: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "verdict": self.verdict,
            "risk_index": self.risk_index,
            "risk_index_note": "Evidence-weighted signal index, not a probability that the seller is fraudulent.",
            "confidence": self.confidence,
            "confidence_note": "Qualitative confidence in the available evidence assessment; not a statistically calibrated probability.",
            "conclusion": self.conclusion,
            "risk_evidence": [e.to_dict() for e in self.risk_evidence],
            "supporting_evidence": [e.to_dict() for e in self.supporting_evidence],
            "context_evidence": [e.to_dict() for e in self.context_evidence],
            "locations": [p.to_dict() for p in self.locations],
            "completed_checks": self.completed_checks,
            "unavailable_checks": self.unavailable_checks,
            "skipped_checks": self.skipped_checks,
            "recommended_actions": self.recommended_actions,
            "limitations": self.limitations,
        }
