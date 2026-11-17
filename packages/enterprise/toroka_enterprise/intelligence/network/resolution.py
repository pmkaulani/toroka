from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class EntityLinkStatus(StrEnum):
    SAME_ENTITY_CONFIRMED = "SAME_ENTITY_CONFIRMED"
    PENDING_SECOND_REVIEW = "PENDING_SECOND_REVIEW"
    POSSIBLY_RELATED = "POSSIBLY_RELATED"
    SHARED_ATTRIBUTE_ONLY = "SHARED_ATTRIBUTE_ONLY"
    RELATIONSHIP_DISPROVEN = "RELATIONSHIP_DISPROVEN"


class AttributeRiskTier(StrEnum):
    STRONG_IDENTIFIER = "strong_identifier"
    COMMODITY_IDENTIFIER = "commodity_identifier"
    EPHEMERAL_INFRASTRUCTURE = "ephemeral_infrastructure"
    UNCLASSIFIED = "unclassified"


def classify_attribute_risk(attribute_type: str) -> AttributeRiskTier:
    """Categorize attribute specificity to prevent accidental identity collapses."""
    attr = (attribute_type or "").lower().strip()
    if attr in ("national_id_hash", "ssn_hash", "tax_id_hash", "passport_hash", "id_number_hash"):
        return AttributeRiskTier.STRONG_IDENTIFIER
    if attr in (
        "phone",
        "telephone",
        "phone_number",
        "email",
        "email_address",
        "device",
        "device_id",
        "mac_address",
        "hardware_fingerprint",
    ):
        return AttributeRiskTier.COMMODITY_IDENTIFIER
    if attr in (
        "ip_address",
        "ip_subnet",
        "branch_workstation",
        "workstation",
        "wifi_bssid",
        "asn",
    ):
        return AttributeRiskTier.EPHEMERAL_INFRASTRUCTURE
    return AttributeRiskTier.UNCLASSIFIED


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
    proposed_by: str | None = None
    first_reviewed_by: str | None = None
    first_reviewed_at: datetime | None = None
    first_review_rationale: str | None = None
    second_reviewed_by: str | None = None
    second_reviewed_at: datetime | None = None
    second_review_rationale: str | None = None
    evidence_digest: str | None = None

    def __post_init__(self) -> None:
        if not self.candidate_id:
            raise ValueError("candidate_id is required")
        if not self.installation_id:
            raise ValueError("installation_id is required")
        if not self.source_entity_key or not self.target_entity_key:
            raise ValueError("Source and target entity keys are required")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {self.confidence}")

        first_by = self.first_reviewed_by or self.reviewed_by
        first_rat = self.first_review_rationale or self.review_rationale
        if first_by and not self.first_reviewed_by:
            object.__setattr__(self, "first_reviewed_by", first_by)
        if first_rat and not self.first_review_rationale:
            object.__setattr__(self, "first_review_rationale", first_rat)

        if self.status == EntityLinkStatus.SAME_ENTITY_CONFIRMED:
            if not self.first_reviewed_by or not self.first_reviewed_by.strip():
                raise ValueError(
                    "SAME_ENTITY_CONFIRMED status requires human maker-checker review with reviewed_by"
                )
            if not self.first_review_rationale or len(self.first_review_rationale.strip()) < 5:
                raise ValueError(
                    "SAME_ENTITY_CONFIRMED status requires human maker-checker review with substantive review_rationale"
                )
            if not self.second_reviewed_by or not self.second_reviewed_by.strip():
                raise ValueError(
                    "SAME_ENTITY_CONFIRMED status requires dual-control second reviewer approval"
                )
            if not self.second_review_rationale or len(self.second_review_rationale.strip()) < 5:
                raise ValueError(
                    "SAME_ENTITY_CONFIRMED status requires substantive second review rationale"
                )
            if self.first_reviewed_by == self.second_reviewed_by:
                raise ValueError(
                    "Maker-checker violation: first and second reviewer must be distinct independent people"
                )
            if self.proposed_by and self.second_reviewed_by == self.proposed_by:
                raise ValueError(
                    "Maker-checker violation: second reviewer cannot be the proposer"
                )
        elif self.status == EntityLinkStatus.PENDING_SECOND_REVIEW:
            if not self.first_reviewed_by or not self.first_reviewed_by.strip():
                raise ValueError(
                    "PENDING_SECOND_REVIEW requires first reviewer"
                )
            if not self.first_review_rationale or len(self.first_review_rationale.strip()) < 5:
                raise ValueError(
                    "PENDING_SECOND_REVIEW requires substantive first review rationale"
                )

    @property
    def is_confirmed_identity(self) -> bool:
        """Strict governance guard: identity confirmation is ONLY valid when dual-control reviewed."""
        return (
            self.status == EntityLinkStatus.SAME_ENTITY_CONFIRMED
            and bool(self.first_reviewed_by and self.first_reviewed_by.strip())
            and bool(self.second_reviewed_by and self.second_reviewed_by.strip())
            and self.first_reviewed_by != self.second_reviewed_by
            and (self.second_reviewed_by != self.proposed_by if self.proposed_by else True)
            and bool(self.first_review_rationale and len(self.first_review_rationale.strip()) >= 5)
            and bool(self.second_review_rationale and len(self.second_review_rationale.strip()) >= 5)
            and len(self.contradicting_evidence) == 0
        )

    @property
    def attribute_risk_tier(self) -> AttributeRiskTier:
        return classify_attribute_risk(self.attribute_type)

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "installation_id": self.installation_id,
            "source_entity_key": self.source_entity_key,
            "target_entity_key": self.target_entity_key,
            "attribute_type": self.attribute_type,
            "attribute_value": self.attribute_value,
            "attribute_risk_tier": self.attribute_risk_tier.value,
            "match_type": self.match_type.value,
            "status": self.status.value,
            "is_confirmed_identity": self.is_confirmed_identity,
            "confidence": self.confidence,
            "supporting_evidence": list(self.supporting_evidence),
            "contradicting_evidence": list(self.contradicting_evidence),
            "source_systems": list(self.source_systems),
            "first_observed": self.first_observed.isoformat() if self.first_observed else None,
            "last_observed": self.last_observed.isoformat() if self.last_observed else None,
            "reviewed_by": self.reviewed_by,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "review_rationale": self.review_rationale,
            "proposed_by": self.proposed_by,
            "first_reviewed_by": self.first_reviewed_by,
            "first_reviewed_at": self.first_reviewed_at.isoformat() if self.first_reviewed_at else None,
            "first_review_rationale": self.first_review_rationale,
            "second_reviewed_by": self.second_reviewed_by,
            "second_reviewed_at": self.second_reviewed_at.isoformat() if self.second_reviewed_at else None,
            "second_review_rationale": self.second_review_rationale,
            "evidence_digest": self.evidence_digest,
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

        if decision == EntityLinkStatus.SAME_ENTITY_CONFIRMED:
            # If already in PENDING_SECOND_REVIEW and reviewer is different, this is the second review
            if candidate.status == EntityLinkStatus.PENDING_SECOND_REVIEW:
                return EntityResolutionEngine.approve_identity_link(
                    candidate=candidate,
                    second_reviewer_subject=reviewer_subject,
                    rationale=rationale,
                    reviewed_at=t,
                )
            # First review: transition to PENDING_SECOND_REVIEW
            return EntityLinkCandidate(
                candidate_id=candidate.candidate_id,
                installation_id=candidate.installation_id,
                source_entity_key=candidate.source_entity_key,
                target_entity_key=candidate.target_entity_key,
                attribute_type=candidate.attribute_type,
                attribute_value=candidate.attribute_value,
                match_type=candidate.match_type,
                status=EntityLinkStatus.PENDING_SECOND_REVIEW,
                confidence=min(0.85, max(candidate.confidence, 0.70)),
                supporting_evidence=candidate.supporting_evidence,
                contradicting_evidence=candidate.contradicting_evidence,
                source_systems=candidate.source_systems,
                first_observed=candidate.first_observed,
                last_observed=candidate.last_observed,
                reviewed_by=reviewer_subject,
                reviewed_at=t,
                review_rationale=rationale.strip(),
                proposed_by=candidate.proposed_by,
                first_reviewed_by=reviewer_subject,
                first_reviewed_at=t,
                first_review_rationale=rationale.strip(),
                second_reviewed_by=None,
                second_reviewed_at=None,
                second_review_rationale=None,
                evidence_digest=candidate.evidence_digest,
            )

        new_conf = candidate.confidence
        if decision == EntityLinkStatus.RELATIONSHIP_DISPROVEN:
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
            proposed_by=candidate.proposed_by,
            first_reviewed_by=reviewer_subject,
            first_reviewed_at=t,
            first_review_rationale=rationale.strip(),
            second_reviewed_by=None,
            second_reviewed_at=None,
            second_review_rationale=None,
            evidence_digest=candidate.evidence_digest,
        )

    @staticmethod
    def approve_identity_link(
        candidate: EntityLinkCandidate,
        second_reviewer_subject: str,
        rationale: str,
        reviewed_at: datetime | None = None,
    ) -> EntityLinkCandidate:
        """Second independent human authoriser confirms candidate identity."""
        if not second_reviewer_subject or not second_reviewer_subject.strip():
            raise ValueError("second_reviewer_subject is required")
        if not rationale or len(rationale.strip()) < 5:
            raise ValueError("A clear, substantive second review rationale is required")
        if candidate.status != EntityLinkStatus.PENDING_SECOND_REVIEW:
            raise ValueError("Candidate must be in PENDING_SECOND_REVIEW before final approval")
        if candidate.first_reviewed_by and second_reviewer_subject == candidate.first_reviewed_by:
            raise ValueError("Maker-checker violation: second reviewer must differ from first reviewer")
        if candidate.proposed_by and second_reviewer_subject == candidate.proposed_by:
            raise ValueError("Maker-checker violation: second reviewer cannot be the proposer")

        t = reviewed_at or datetime.now(timezone.utc)
        return EntityLinkCandidate(
            candidate_id=candidate.candidate_id,
            installation_id=candidate.installation_id,
            source_entity_key=candidate.source_entity_key,
            target_entity_key=candidate.target_entity_key,
            attribute_type=candidate.attribute_type,
            attribute_value=candidate.attribute_value,
            match_type=candidate.match_type,
            status=EntityLinkStatus.SAME_ENTITY_CONFIRMED,
            confidence=1.0,
            supporting_evidence=candidate.supporting_evidence,
            contradicting_evidence=candidate.contradicting_evidence,
            source_systems=candidate.source_systems,
            first_observed=candidate.first_observed,
            last_observed=candidate.last_observed,
            reviewed_by=second_reviewer_subject,
            reviewed_at=t,
            review_rationale=rationale.strip(),
            proposed_by=candidate.proposed_by,
            first_reviewed_by=candidate.first_reviewed_by,
            first_reviewed_at=candidate.first_reviewed_at,
            first_review_rationale=candidate.first_review_rationale,
            second_reviewed_by=second_reviewer_subject,
            second_reviewed_at=t,
            second_review_rationale=rationale.strip(),
            evidence_digest=candidate.evidence_digest,
        )


def can_collapse_entities(candidate: EntityLinkCandidate) -> bool:
    """Strict identity collapsing gate.

    Prevents probabilistic or single-person identity collapse. Returns True ONLY when:
    1. The candidate is explicitly confirmed via two-person maker-checker review (is_confirmed_identity is True).
    2. Ephemeral infrastructure attributes (IP address, subnet, branch workstation) NEVER collapse entities
       into a single physical person on their own, even after two reviewers.
    3. Commodity identifiers (phone, email, device) require corroborated evidence and zero contradictions.
    """
    if not candidate.is_confirmed_identity:
        return False
    risk = classify_attribute_risk(candidate.attribute_type)
    if risk == AttributeRiskTier.EPHEMERAL_INFRASTRUCTURE:
        return False
    if risk == AttributeRiskTier.COMMODITY_IDENTIFIER:
        if len(candidate.contradicting_evidence) > 0:
            return False
    return True


def approve_identity_link(
    candidate: EntityLinkCandidate,
    second_reviewer_subject: str,
    rationale: str,
    reviewed_at: datetime | None = None,
) -> EntityLinkCandidate:
    return EntityResolutionEngine.approve_identity_link(
        candidate=candidate,
        second_reviewer_subject=second_reviewer_subject,
        rationale=rationale,
        reviewed_at=reviewed_at,
    )

