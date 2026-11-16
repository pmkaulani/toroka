from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class EntityLinkStatus(StrEnum):
    SAME_ENTITY_CONFIRMED = "SAME_ENTITY_CONFIRMED"
    POSSIBLY_RELATED = "POSSIBLY_RELATED"
    SHARED_ATTRIBUTE_ONLY = "SHARED_ATTRIBUTE_ONLY"
    RELATIONSHIP_DISPROVEN = "RELATIONSHIP_DISPROVEN"


class MatchType(StrEnum):
    EXACT = "exact"
    NORMALIZED = "normalized"
    DERIVED = "derived"


@dataclass(frozen=True)
class EntityLinkCandidate:
    candidate_id: str
    installation_id: str
    source_entity_key: str
    target_entity_key: str
    attribute_type: str
    attribute_value: str
    match_type: MatchType
    status: EntityLinkStatus
    confidence: float
    supporting_evidence: tuple[dict[str, Any], ...] = ()
    contradicting_evidence: tuple[dict[str, Any], ...] = ()
    source_systems: tuple[str, ...] = ()
    first_observed: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_observed: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    review_rationale: str | None = None

    def __post_init__(self) -> None:
        if not self.candidate_id:
            raise ValueError("candidate_id is required")
        if not self.installation_id:
            raise ValueError("installation_id is required")
        if not self.source_entity_key or not self.target_entity_key:
            raise ValueError("Source and target entity keys are required")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {self.confidence}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "installation_id": self.installation_id,
            "source_entity_key": self.source_entity_key,
            "target_entity_key": self.target_entity_key,
            "attribute_type": self.attribute_type,
            "attribute_value": self.attribute_value,
            "match_type": self.match_type.value,
            "status": self.status.value,
            "confidence": self.confidence,
            "supporting_evidence": list(self.supporting_evidence),
            "contradicting_evidence": list(self.contradicting_evidence),
            "source_systems": list(self.source_systems),
            "first_observed": self.first_observed.isoformat() if self.first_observed else None,
            "last_observed": self.last_observed.isoformat() if self.last_observed else None,
            "reviewed_by": self.reviewed_by,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "review_rationale": self.review_rationale,
        }


def normalize_identifier(attribute_type: str, raw_value: str) -> str:
    """Deterministic normalization for phone numbers, emails, and device IDs."""
    raw = raw_value.strip()
    if attribute_type in ("phone", "telephone", "phone_number"):
        digits = "".join(c for c in raw if c.isdigit())
        return digits[-10:] if len(digits) >= 10 else digits
    if attribute_type in ("email", "email_address"):
        return raw.lower()
    if attribute_type in ("device", "device_id", "mac_address"):
        return raw.lower().replace("-", ":")
    return raw.lower()


class EntityResolutionEngine:
    """Controlled entity resolution and link governance engine with maker-checker auditability."""

    @staticmethod
    def generate_candidate_id(
        installation_id: str,
        source_key: str,
        target_key: str,
        attr_type: str,
        attr_val: str,
    ) -> str:
        canonical_pair = sorted([source_key, target_key])
        seed = f"{installation_id}:{canonical_pair[0]}:{canonical_pair[1]}:{attr_type}:{attr_val}"
        return "cand_" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:20]

    @staticmethod
    def propose_candidate(
        installation_id: str,
        source_key: str,
        target_key: str,
        attribute_type: str,
        attribute_value: str,
        source_systems: list[str],
        supporting_evidence: list[dict[str, Any]] | None = None,
        contradicting_evidence: list[dict[str, Any]] | None = None,
        observed_time: datetime | None = None,
    ) -> EntityLinkCandidate:
        """Create a candidate link between two entities based on a shared attribute."""
        if source_key == target_key:
            raise ValueError("Cannot link entity to itself")

        t = observed_time or datetime.now(timezone.utc)
        normalized = normalize_identifier(attribute_type, attribute_value)
        cid = EntityResolutionEngine.generate_candidate_id(
            installation_id, source_key, target_key, attribute_type, normalized
        )

        # Baseline confidence based on attribute specificity
        if attribute_type in ("national_id_hash", "ssn_hash", "tax_id_hash"):
            base_conf = 0.90
            initial_status = EntityLinkStatus.POSSIBLY_RELATED
        elif attribute_type in ("phone", "email"):
            base_conf = 0.65
            initial_status = EntityLinkStatus.POSSIBLY_RELATED
        elif attribute_type in ("device_id", "hardware_fingerprint"):
            base_conf = 0.50
            initial_status = EntityLinkStatus.SHARED_ATTRIBUTE_ONLY
        elif attribute_type in ("ip_address", "ip_subnet", "branch_workstation"):
            base_conf = 0.25
            initial_status = EntityLinkStatus.SHARED_ATTRIBUTE_ONLY
        else:
            base_conf = 0.40
            initial_status = EntityLinkStatus.SHARED_ATTRIBUTE_ONLY

        # Penalize if contradicting evidence exists
        contra = contradicting_evidence or []
        supp = supporting_evidence or []
        if contra:
            base_conf = max(0.05, base_conf - (0.20 * len(contra)))

        return EntityLinkCandidate(
            candidate_id=cid,
            installation_id=installation_id,
            source_entity_key=source_key,
            target_entity_key=target_key,
            attribute_type=attribute_type,
            attribute_value=normalized,
            match_type=MatchType.NORMALIZED if normalized != attribute_value else MatchType.EXACT,
            status=initial_status,
            confidence=round(base_conf, 2),
            supporting_evidence=tuple(supp),
            contradicting_evidence=tuple(contra),
            source_systems=tuple(sorted(set(source_systems))),
            first_observed=t,
            last_observed=t,
        )

    @staticmethod
    def apply_human_review(
        candidate: EntityLinkCandidate,
        reviewer_subject: str,
        decision: EntityLinkStatus,
        rationale: str,
        reviewed_at: datetime | None = None,
    ) -> EntityLinkCandidate:
        """Apply human investigator / authoriser decision with mandatory rationale."""
        if not reviewer_subject or not reviewer_subject.strip():
            raise ValueError("reviewer_subject is required")
        if not rationale or len(rationale.strip()) < 5:
            raise ValueError("A clear, substantive review rationale is required")

        t = reviewed_at or datetime.now(timezone.utc)
        new_conf = candidate.confidence
        if decision == EntityLinkStatus.SAME_ENTITY_CONFIRMED:
            new_conf = 1.0
        elif decision == EntityLinkStatus.RELATIONSHIP_DISPROVEN:
            new_conf = 0.0
        elif decision == EntityLinkStatus.SHARED_ATTRIBUTE_ONLY:
            new_conf = min(0.3, candidate.confidence)

        return EntityLinkCandidate(
            candidate_id=candidate.candidate_id,
            installation_id=candidate.installation_id,
            source_entity_key=candidate.source_entity_key,
            target_entity_key=candidate.target_entity_key,
            attribute_type=candidate.attribute_type,
            attribute_value=candidate.attribute_value,
            match_type=candidate.match_type,
            status=decision,
            confidence=new_conf,
            supporting_evidence=candidate.supporting_evidence,
            contradicting_evidence=candidate.contradicting_evidence,
            source_systems=candidate.source_systems,
            first_observed=candidate.first_observed,
            last_observed=candidate.last_observed,
            reviewed_by=reviewer_subject,
            reviewed_at=t,
            review_rationale=rationale.strip(),
        )
