"""API router for Phase 9: Fraud DNA & Institutional Memory Engine."""
from __future__ import annotations

import logging
from typing import Any
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from ..auth import EnterprisePrincipal, get_current_principal, require_roles
from ..dependencies import get_db, get_installation_id
from ..permissions import (
    ROLE_AUDITOR,
    ROLE_AUTHORISER,
    ROLE_INVESTIGATOR,
    ROLE_SYSTEM_ADMINISTRATOR,
)
from ..services.memory import MemoryService
from ..memory_schemas import (
    CaseSimilarityResponse,
    FingerprintResponse,
    InstitutionalPatternCreate,
    InstitutionalPatternResponse,
    MemoryOverviewResponse,
    PatternEvaluationResponse,
    PatternMatchResponse,
    PatternReviewRequest,
    PatternReviewResponse,
    PatternVersionResponse,
)

logger = logging.getLogger(__name__)


def _primary_role(principal: EnterprisePrincipal) -> str:
    return sorted(principal.roles)[0] if principal.roles else "investigator"


router = APIRouter(
    prefix="/api/enterprise/v1/memory",
    tags=["Institutional Memory & Fraud DNA"],
)


@router.get(
    "/overview",
    response_model=MemoryOverviewResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def get_memory_overview(
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> MemoryOverviewResponse:
    """Retrieve institutional memory health, pattern counts, and review metrics."""
    svc = MemoryService(db, principal.installation_id or installation_id)
    ov = svc.get_overview()

    review_responses = [
        PatternReviewResponse(
            review_id=r.review_id,
            pattern_id=r.pattern_id,
            pattern_version=r.pattern_version,
            reviewer_subject=r.reviewer_subject,
            action=r.action,
            rationale=r.rationale,
            created_at=r.created_at.isoformat(),
        )
        for r in ov["recent_reviews"]
    ]

    return MemoryOverviewResponse(
        adjudicated_case_count=ov["adjudicated_case_count"],
        validated_pattern_count=ov["validated_pattern_count"],
        candidate_pattern_count=ov["candidate_pattern_count"],
        under_review_pattern_count=ov["under_review_pattern_count"],
        suspended_pattern_count=ov["suspended_pattern_count"],
        retired_pattern_count=ov["retired_pattern_count"],
        average_source_coverage=ov["average_source_coverage"],
        total_fingerprinted_cases=ov["total_fingerprinted_cases"],
        recent_reviews=review_responses,
    )


@router.post(
    "/patterns/discover",
    response_model=list[InstitutionalPatternResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def discover_patterns(
    min_support: int = Query(2, ge=2, description="Minimum confirmed fraud cases required"),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> list[InstitutionalPatternResponse]:
    """Mine candidate institutional patterns from adjudicated cases."""
    svc = MemoryService(db, principal.installation_id or installation_id)
    candidates = svc.discover_candidates(
        curator_subject=principal.subject,
        curator_role=_primary_role(principal),
        min_support=min_support,
    )
    return [
        InstitutionalPatternResponse(
            pattern_id=c.pattern_id,
            installation_id=c.installation_id,
            version=c.version,
            title=c.title,
            description=c.description,
            feature_signature=dict(c.feature_signature or {}),
            confirmed_fraud_case_ids=[],
            confirmed_legitimate_case_ids=[],
            independent_source_systems=list(c.independent_source_systems or []),
            status=c.status,
            extractor_version=c.extractor_version,
            control_weaknesses=list(c.control_weaknesses or []),
            curator_subject=c.curator_subject,
            reviewer_subject=c.reviewer_subject,
            reviewed_at=c.reviewed_at.isoformat() if c.reviewed_at else None,
            validation_rationale=c.validation_rationale,
            limitations=list(c.limitations or []),
            created_at=c.created_at.isoformat(),
            updated_at=c.updated_at.isoformat() if c.updated_at else None,
        )
        for c in candidates
    ]


@router.post(
    "/patterns/candidates",
    response_model=InstitutionalPatternResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def create_candidate_pattern(
    payload: InstitutionalPatternCreate,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> InstitutionalPatternResponse:
    """Manually curate a new candidate institutional pattern."""
    svc = MemoryService(db, principal.installation_id or installation_id)
    rec = svc.create_custom_pattern(
        payload=payload,
        curator_subject=principal.subject,
        curator_role=_primary_role(principal),
    )
    return InstitutionalPatternResponse(
        pattern_id=rec.pattern_id,
        installation_id=rec.installation_id,
        version=rec.version,
        title=rec.title,
        description=rec.description,
        feature_signature=dict(rec.feature_signature or {}),
        confirmed_fraud_case_ids=payload.confirmed_fraud_case_ids,
        confirmed_legitimate_case_ids=payload.confirmed_legitimate_case_ids,
        independent_source_systems=list(rec.independent_source_systems or []),
        status=rec.status,
        extractor_version=rec.extractor_version,
        control_weaknesses=list(rec.control_weaknesses or []),
        curator_subject=rec.curator_subject,
        reviewer_subject=rec.reviewer_subject,
        reviewed_at=rec.reviewed_at.isoformat() if rec.reviewed_at else None,
        validation_rationale=rec.validation_rationale,
        limitations=list(rec.limitations or []),
        created_at=rec.created_at.isoformat(),
        updated_at=rec.updated_at.isoformat() if rec.updated_at else None,
    )


@router.get(
    "/patterns",
    response_model=list[InstitutionalPatternResponse],
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def list_patterns(
    status: str | None = Query(None, description="Optional status filter: candidate, validated, suspended, retired"),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> list[InstitutionalPatternResponse]:
    """List institutional patterns in this installation."""
    svc = MemoryService(db, principal.installation_id or installation_id)
    patterns = svc.list_patterns(status_filter=status)
    results: list[InstitutionalPatternResponse] = []
    for p in patterns:
        dp = svc._record_to_domain_pattern(p)
        results.append(
            InstitutionalPatternResponse(
                pattern_id=p.pattern_id,
                installation_id=p.installation_id,
                version=p.version,
                title=p.title,
                description=p.description,
                feature_signature=dict(p.feature_signature or {}),
                confirmed_fraud_case_ids=list(dp.confirmed_fraud_case_ids),
                confirmed_legitimate_case_ids=list(dp.confirmed_legitimate_case_ids),
                independent_source_systems=list(p.independent_source_systems or []),
                status=p.status,
                extractor_version=p.extractor_version,
                control_weaknesses=list(p.control_weaknesses or []),
                curator_subject=p.curator_subject,
                reviewer_subject=p.reviewer_subject,
                reviewed_at=p.reviewed_at.isoformat() if p.reviewed_at else None,
                validation_rationale=p.validation_rationale,
                limitations=list(p.limitations or []),
                created_at=p.created_at.isoformat(),
                updated_at=p.updated_at.isoformat() if p.updated_at else None,
            )
        )
    return results


@router.get(
    "/patterns/{pattern_id}",
    response_model=InstitutionalPatternResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def get_pattern(
    pattern_id: str,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> InstitutionalPatternResponse:
    """Retrieve details of a specific pattern."""
    svc = MemoryService(db, principal.installation_id or installation_id)
    rec = svc.get_pattern(pattern_id)
    dp = svc._record_to_domain_pattern(rec)
    return InstitutionalPatternResponse(
        pattern_id=rec.pattern_id,
        installation_id=rec.installation_id,
        version=rec.version,
        title=rec.title,
        description=rec.description,
        feature_signature=dict(rec.feature_signature or {}),
        confirmed_fraud_case_ids=list(dp.confirmed_fraud_case_ids),
        confirmed_legitimate_case_ids=list(dp.confirmed_legitimate_case_ids),
        independent_source_systems=list(rec.independent_source_systems or []),
        status=rec.status,
        extractor_version=rec.extractor_version,
        control_weaknesses=list(rec.control_weaknesses or []),
        curator_subject=rec.curator_subject,
        reviewer_subject=rec.reviewer_subject,
        reviewed_at=rec.reviewed_at.isoformat() if rec.reviewed_at else None,
        validation_rationale=rec.validation_rationale,
        limitations=list(rec.limitations or []),
        created_at=rec.created_at.isoformat(),
        updated_at=rec.updated_at.isoformat() if rec.updated_at else None,
    )


@router.get(
    "/patterns/{pattern_id}/evaluate",
    response_model=PatternEvaluationResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def evaluate_pattern(
    pattern_id: str,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> PatternEvaluationResponse:
    """Evaluate whether candidate pattern meets institutional validation thresholds."""
    svc = MemoryService(db, principal.installation_id or installation_id)
    rec = svc.get_pattern(pattern_id)
    res = svc.evaluate_pattern_for_validation(pattern_id)
    return PatternEvaluationResponse(
        pattern_id=pattern_id,
        version=rec.version,
        eligible_for_review=res.eligible_for_review,
        checks=res.checks,
        blockers=list(res.blockers),
        details=res.details,
    )


@router.post(
    "/patterns/{pattern_id}/review",
    response_model=InstitutionalPatternResponse,
    dependencies=[Depends(require_roles(ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def review_pattern(
    pattern_id: str,
    payload: PatternReviewRequest,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> InstitutionalPatternResponse:
    """Perform a dual-control review (submit_for_review, validate, reject, suspend, reinstate, retire)."""
    svc = MemoryService(db, principal.installation_id or installation_id)
    rec = svc.review_pattern_lifecycle(
        pattern_id=pattern_id,
        action=payload.action,
        rationale=payload.rationale,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )
    dp = svc._record_to_domain_pattern(rec)
    return InstitutionalPatternResponse(
        pattern_id=rec.pattern_id,
        installation_id=rec.installation_id,
        version=rec.version,
        title=rec.title,
        description=rec.description,
        feature_signature=dict(rec.feature_signature or {}),
        confirmed_fraud_case_ids=list(dp.confirmed_fraud_case_ids),
        confirmed_legitimate_case_ids=list(dp.confirmed_legitimate_case_ids),
        independent_source_systems=list(rec.independent_source_systems or []),
        status=rec.status,
        extractor_version=rec.extractor_version,
        control_weaknesses=list(rec.control_weaknesses or []),
        curator_subject=rec.curator_subject,
        reviewer_subject=rec.reviewer_subject,
        reviewed_at=rec.reviewed_at.isoformat() if rec.reviewed_at else None,
        validation_rationale=rec.validation_rationale,
        limitations=list(rec.limitations or []),
        created_at=rec.created_at.isoformat(),
        updated_at=rec.updated_at.isoformat() if rec.updated_at else None,
    )


@router.get(
    "/patterns/{pattern_id}/versions",
    response_model=list[PatternVersionResponse],
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def list_pattern_versions(
    pattern_id: str,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> list[PatternVersionResponse]:
    """Retrieve immutable audit history of pattern revisions."""
    svc = MemoryService(db, principal.installation_id or installation_id)
    versions = svc.list_pattern_versions(pattern_id)
    return [
        PatternVersionResponse(
            pattern_id=v.pattern_id,
            version=v.version,
            title=v.title,
            description=v.description,
            feature_signature=dict(v.feature_signature or {}),
            status=v.status,
            changed_by=v.changed_by,
            change_summary=v.change_summary,
            created_at=v.created_at.isoformat(),
        )
        for v in versions
    ]


@router.get(
    "/cases/{case_id}/fingerprint",
    response_model=FingerprintResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def get_case_fingerprint(
    case_id: str,
    refresh: bool = Query(False, description="Force re-extraction of case fingerprint"),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> FingerprintResponse:
    """Retrieve or compute zero-PII behavioral fingerprint for an investigation."""
    svc = MemoryService(db, principal.installation_id or installation_id)
    fp = svc.get_or_build_fingerprint(case_id, force_refresh=refresh)
    return FingerprintResponse(
        case_id=fp.case_id,
        installation_id=fp.installation_id,
        extractor_version=fp.extractor_version,
        features=dict(fp.features),
        source_systems=list(fp.source_systems),
        source_coverage=fp.source_coverage,
        total_events=fp.total_events,
        first_event_time=fp.first_event_time.isoformat() if fp.first_event_time else None,
        last_event_time=fp.last_event_time.isoformat() if fp.last_event_time else None,
        control_weaknesses=list(fp.control_weaknesses),
        adjudicated_label=fp.adjudicated_label,
        created_at=fp.created_at.isoformat(),
    )


@router.get(
    "/cases/{case_id}/similar",
    response_model=list[CaseSimilarityResponse],
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def get_similar_historical_cases(
    case_id: str,
    limit: int = Query(10, ge=1, le=50),
    min_coverage: float = Query(0.1, ge=0.0, le=1.0),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> list[CaseSimilarityResponse]:
    """Retrieve historical cases ranked by deterministic feature similarity."""
    svc = MemoryService(db, principal.installation_id or installation_id)
    similarities = svc.search_similar_historical_cases(
        case_id=case_id,
        limit=limit,
        min_coverage=min_coverage,
    )
    return [
        CaseSimilarityResponse(
            current_case_id=s.current_case_id,
            historical_case_id=s.historical_case_id,
            similarity_index=s.similarity_index,
            comparison_coverage=s.comparison_coverage,
            matched_features=list(s.matched_features),
            different_features=list(s.different_features),
            historical_outcome=s.historical_outcome,
            historical_control_weaknesses=list(s.historical_control_weaknesses),
            shared_control_weaknesses=list(s.shared_control_weaknesses),
            summary_explanation=s.summary_explanation,
        )
        for s in similarities
    ]


@router.get(
    "/cases/{case_id}/patterns",
    response_model=list[PatternMatchResponse],
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def match_case_patterns(
    case_id: str,
    min_coverage: float = Query(0.1, ge=0.0, le=1.0),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> list[PatternMatchResponse]:
    """Match investigation against institutional patterns in this installation."""
    svc = MemoryService(db, principal.installation_id or installation_id)
    matches = svc.match_case_against_patterns(case_id=case_id, min_coverage=min_coverage)
    return [
        PatternMatchResponse(
            pattern_id=m.pattern_id,
            pattern_version=m.pattern_version,
            pattern_title=m.pattern_title,
            pattern_status=m.pattern_status,
            similarity_index=m.similarity_index,
            comparison_coverage=m.comparison_coverage,
            matched_features=list(m.matched_features),
            different_features=list(m.different_features),
            control_weaknesses=list(m.control_weaknesses),
            explanation=m.explanation,
            confirmed_fraud_cases_count=m.confirmed_fraud_cases_count,
            confirmed_legitimate_cases_count=m.confirmed_legitimate_cases_count,
        )
        for m in matches
    ]
