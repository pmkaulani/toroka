from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class PatternStatus(StrEnum):
    CANDIDATE = "candidate"
    UNDER_REVIEW = "under_review"
    VALIDATED = "validated"
    SUSPENDED = "suspended"
    RETIRED = "retired"


@dataclass(frozen=True)
class InstitutionalPattern:
    """A governed institutional intelligence pattern representing a recurring fraud method or control bypass."""

    pattern_id: str
    installation_id: str
    version: int
    title: str
    description: str
    feature_signature: dict[str, str]
    confirmed_fraud_case_ids: tuple[str, ...]
    confirmed_legitimate_case_ids: tuple[str, ...]
    independent_source_systems: tuple[str, ...]
    status: PatternStatus
    created_by: str
    created_at: datetime
    extractor_version: str = "v1"
    supporting_event_ids: tuple[str, ...] = ()
    control_weaknesses: tuple[str, ...] = ()
    curator: str = "system"
    reviewer: str | None = None
    reviewed_at: datetime | None = None
    validation_rationale: str | None = None
    limitations: tuple[str, ...] = ()
    updated_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "installation_id": self.installation_id,
            "version": self.version,
            "title": self.title,
            "description": self.description,
            "feature_signature": dict(self.feature_signature),
            "confirmed_fraud_case_ids": list(self.confirmed_fraud_case_ids),
            "confirmed_legitimate_case_ids": list(self.confirmed_legitimate_case_ids),
            "independent_source_systems": list(self.independent_source_systems),
            "status": self.status.value,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat(),
            "extractor_version": self.extractor_version,
            "supporting_event_ids": list(self.supporting_event_ids),
            "control_weaknesses": list(self.control_weaknesses),
            "curator": self.curator,
            "reviewer": self.reviewer,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "validation_rationale": self.validation_rationale,
            "limitations": list(self.limitations),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


@dataclass(frozen=True)
class PatternValidationPolicy:
    """Configurable institutional governance policy for pattern validation."""

    min_confirmed_fraud_cases: int = 2
    min_confirmed_legitimate_cases: int = 1
    min_independent_sources: int = 2
    min_source_coverage: float = 0.4
    require_independent_reviewer: bool = True
    allowed_extractor_versions: tuple[str, ...] = ("v1",)


@dataclass(frozen=True)
class PatternValidationResult:
    """Structured evaluation of whether a pattern candidate meets validation criteria."""

    eligible_for_review: bool
    checks: dict[str, bool]
    blockers: tuple[str, ...]
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "eligible_for_review": self.eligible_for_review,
            "checks": dict(self.checks),
            "blockers": list(self.blockers),
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class PatternReview:
    """Audit review action for pattern lifecycle transitions."""

    review_id: str
    pattern_id: str
    pattern_version: int
    reviewer_subject: str
    action: str  # submit_for_review, validate, reject, suspend, reinstate, retire
    rationale: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "review_id": self.review_id,
            "pattern_id": self.pattern_id,
            "pattern_version": self.pattern_version,
            "reviewer_subject": self.reviewer_subject,
            "action": self.action,
            "rationale": self.rationale,
            "created_at": self.created_at.isoformat(),
        }


def evaluate_pattern(
    pattern: InstitutionalPattern,
    policy: PatternValidationPolicy | None = None,
) -> PatternValidationResult:
    """Evaluate candidate pattern against institutional validation policy."""
    pol = policy or PatternValidationPolicy()
    checks: dict[str, bool] = {}
    blockers: list[str] = []

    # 1. Minimum confirmed fraud cases
    fraud_count = len(pattern.confirmed_fraud_case_ids)
    check_fraud = fraud_count >= pol.min_confirmed_fraud_cases
    checks["sufficient_confirmed_fraud_cases"] = check_fraud
    if not check_fraud:
        blockers.append(
            f"Pattern has {fraud_count} confirmed fraud case(s); requires at least {pol.min_confirmed_fraud_cases}."
        )

    # 2. Minimum confirmed legitimate comparison cases
    legit_count = len(pattern.confirmed_legitimate_case_ids)
    check_legit = legit_count >= pol.min_confirmed_legitimate_cases
    checks["sufficient_legitimate_comparisons"] = check_legit
    if not check_legit:
        blockers.append(
            f"Pattern has {legit_count} confirmed legitimate comparison(s); requires at least {pol.min_confirmed_legitimate_cases} to prevent false positives."
        )

    # 3. Minimum independent source systems
    source_count = len(pattern.independent_source_systems)
    check_sources = source_count >= pol.min_independent_sources
    checks["sufficient_independent_sources"] = check_sources
    if not check_sources:
        blockers.append(
            f"Pattern derives from {source_count} source system(s); requires at least {pol.min_independent_sources} independent sources."
        )

    # 4. Extractor version compatibility
    check_ver = pattern.extractor_version in pol.allowed_extractor_versions
    checks["extractor_version_compatible"] = check_ver
    if not check_ver:
        blockers.append(
            f"Extractor version '{pattern.extractor_version}' is not permitted in policy: {pol.allowed_extractor_versions}."
        )

    # 5. Non-empty feature signature
    check_features = bool(pattern.feature_signature)
    checks["feature_signature_present"] = check_features
    if not check_features:
        blockers.append("Pattern feature signature is empty.")

    eligible = all(checks.values())

    return PatternValidationResult(
        eligible_for_review=eligible,
        checks=checks,
        blockers=tuple(blockers),
        details={
            "fraud_case_count": fraud_count,
            "legitimate_case_count": legit_count,
            "independent_sources_count": source_count,
            "extractor_version": pattern.extractor_version,
            "feature_count": len(pattern.feature_signature),
        },
    )


def approve_pattern(
    pattern: InstitutionalPattern,
    reviewer_subject: str,
    rationale: str,
    policy: PatternValidationPolicy | None = None,
) -> InstitutionalPattern:
    """Validate and approve an institutional pattern under dual-control maker-checker rules."""
    pol = policy or PatternValidationPolicy()

    # Maker-checker control: curator cannot approve own pattern
    if pol.require_independent_reviewer:
        if reviewer_subject == pattern.curator:
            raise ValueError(
                f"Maker-checker violation: Curator '{reviewer_subject}' cannot approve own pattern."
            )
        if reviewer_subject == pattern.created_by:
            raise ValueError(
                f"Maker-checker violation: Creator '{reviewer_subject}' cannot approve own pattern."
            )

    if pattern.status not in (PatternStatus.CANDIDATE, PatternStatus.UNDER_REVIEW):
        raise ValueError(
            f"Cannot approve pattern in status '{pattern.status}'. Must be candidate or under_review."
        )

    eval_result = evaluate_pattern(pattern, pol)
    if not eval_result.eligible_for_review:
        raise ValueError(
            f"Pattern validation policy requirements not satisfied: {'; '.join(eval_result.blockers)}"
        )

    now = datetime.now(timezone.utc)
    return InstitutionalPattern(
        pattern_id=pattern.pattern_id,
        installation_id=pattern.installation_id,
        version=pattern.version,
        title=pattern.title,
        description=pattern.description,
        feature_signature=dict(pattern.feature_signature),
        confirmed_fraud_case_ids=pattern.confirmed_fraud_case_ids,
        confirmed_legitimate_case_ids=pattern.confirmed_legitimate_case_ids,
        independent_source_systems=pattern.independent_source_systems,
        status=PatternStatus.VALIDATED,
        created_by=pattern.created_by,
        created_at=pattern.created_at,
        extractor_version=pattern.extractor_version,
        supporting_event_ids=pattern.supporting_event_ids,
        control_weaknesses=pattern.control_weaknesses,
        curator=pattern.curator,
        reviewer=reviewer_subject,
        reviewed_at=now,
        validation_rationale=rationale,
        limitations=pattern.limitations,
        updated_at=now,
    )


def reject_pattern(
    pattern: InstitutionalPattern,
    reviewer_subject: str,
    rationale: str,
) -> InstitutionalPattern:
    """Reject candidate pattern validation and return it to candidate status with rationale recorded."""
    now = datetime.now(timezone.utc)
    return InstitutionalPattern(
        pattern_id=pattern.pattern_id,
        installation_id=pattern.installation_id,
        version=pattern.version,
        title=pattern.title,
        description=pattern.description,
        feature_signature=dict(pattern.feature_signature),
        confirmed_fraud_case_ids=pattern.confirmed_fraud_case_ids,
        confirmed_legitimate_case_ids=pattern.confirmed_legitimate_case_ids,
        independent_source_systems=pattern.independent_source_systems,
        status=PatternStatus.CANDIDATE,
        created_by=pattern.created_by,
        created_at=pattern.created_at,
        extractor_version=pattern.extractor_version,
        supporting_event_ids=pattern.supporting_event_ids,
        control_weaknesses=pattern.control_weaknesses,
        curator=pattern.curator,
        reviewer=reviewer_subject,
        reviewed_at=now,
        validation_rationale=f"REJECTED: {rationale}",
        limitations=pattern.limitations,
        updated_at=now,
    )


def suspend_pattern(
    pattern: InstitutionalPattern,
    actor_subject: str,
    rationale: str,
) -> InstitutionalPattern:
    """Suspend a validated pattern due to stale evidence, taxonomy updates, or contradictory cases."""
    now = datetime.now(timezone.utc)
    return InstitutionalPattern(
        pattern_id=pattern.pattern_id,
        installation_id=pattern.installation_id,
        version=pattern.version,
        title=pattern.title,
        description=pattern.description,
        feature_signature=dict(pattern.feature_signature),
        confirmed_fraud_case_ids=pattern.confirmed_fraud_case_ids,
        confirmed_legitimate_case_ids=pattern.confirmed_legitimate_case_ids,
        independent_source_systems=pattern.independent_source_systems,
        status=PatternStatus.SUSPENDED,
        created_by=pattern.created_by,
        created_at=pattern.created_at,
        extractor_version=pattern.extractor_version,
        supporting_event_ids=pattern.supporting_event_ids,
        control_weaknesses=pattern.control_weaknesses,
        curator=pattern.curator,
        reviewer=pattern.reviewer,
        reviewed_at=pattern.reviewed_at,
        validation_rationale=f"SUSPENDED by {actor_subject}: {rationale}",
        limitations=pattern.limitations,
        updated_at=now,
    )


def reinstate_pattern(
    pattern: InstitutionalPattern,
    actor_subject: str,
    rationale: str,
) -> InstitutionalPattern:
    """Reinstate a suspended pattern after review."""
    now = datetime.now(timezone.utc)
    return InstitutionalPattern(
        pattern_id=pattern.pattern_id,
        installation_id=pattern.installation_id,
        version=pattern.version,
        title=pattern.title,
        description=pattern.description,
        feature_signature=dict(pattern.feature_signature),
        confirmed_fraud_case_ids=pattern.confirmed_fraud_case_ids,
        confirmed_legitimate_case_ids=pattern.confirmed_legitimate_case_ids,
        independent_source_systems=pattern.independent_source_systems,
        status=PatternStatus.VALIDATED,
        created_by=pattern.created_by,
        created_at=pattern.created_at,
        extractor_version=pattern.extractor_version,
        supporting_event_ids=pattern.supporting_event_ids,
        control_weaknesses=pattern.control_weaknesses,
        curator=pattern.curator,
        reviewer=pattern.reviewer,
        reviewed_at=pattern.reviewed_at,
        validation_rationale=f"REINSTATED by {actor_subject}: {rationale}",
        limitations=pattern.limitations,
        updated_at=now,
    )


def retire_pattern(
    pattern: InstitutionalPattern,
    actor_subject: str,
    rationale: str,
) -> InstitutionalPattern:
    """Permanently retire an institutional pattern."""
    now = datetime.now(timezone.utc)
    return InstitutionalPattern(
        pattern_id=pattern.pattern_id,
        installation_id=pattern.installation_id,
        version=pattern.version,
        title=pattern.title,
        description=pattern.description,
        feature_signature=dict(pattern.feature_signature),
        confirmed_fraud_case_ids=pattern.confirmed_fraud_case_ids,
        confirmed_legitimate_case_ids=pattern.confirmed_legitimate_case_ids,
        independent_source_systems=pattern.independent_source_systems,
        status=PatternStatus.RETIRED,
        created_by=pattern.created_by,
        created_at=pattern.created_at,
        extractor_version=pattern.extractor_version,
        supporting_event_ids=pattern.supporting_event_ids,
        control_weaknesses=pattern.control_weaknesses,
        curator=pattern.curator,
        reviewer=pattern.reviewer,
        reviewed_at=pattern.reviewed_at,
        validation_rationale=f"RETIRED by {actor_subject}: {rationale}",
        limitations=pattern.limitations,
        updated_at=now,
    )
