"""API router for behavioral baselines, anomaly detection, admission control, and investigation prioritization."""
from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..auth import EnterprisePrincipal, get_current_principal, require_roles
from ..dependencies import get_db, get_installation_id
from ..baseline_schemas import (
    BehavioralProfileResponse,
    BehavioralAnomalyResponse,
    EvaluateObservationRequest,
    InvestigationPriorityResponse,
    DetectionMethodResponse,
    BaselineAdmissionRequest,
    BaselineAdmissionResponse,
)
from ..permissions import (
    ROLE_AUDITOR,
    ROLE_AUTHORISER,
    ROLE_INVESTIGATOR,
    ROLE_SYSTEM_ADMINISTRATOR,
)
from ..services.baselines import BaselineService

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/enterprise/v1/baselines",
    tags=["Enterprise Behavioral Baselines & Prioritization"],
)


@router.get(
    "/profiles/{subject_type}/{subject_id}",
    response_model=BehavioralProfileResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR, ROLE_AUDITOR))],
)
def get_behavioral_profile(
    subject_type: str,
    subject_id: str,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> BehavioralProfileResponse:
    """Retrieve or initialize behavioral profile for an authorized subject."""
    svc = BaselineService(db)
    profile = svc.get_or_create_profile(
        installation_id=installation_id,
        subject_type=subject_type,
        subject_id=subject_id,
    )
    return BehavioralProfileResponse.model_validate(profile)


@router.post(
    "/profiles/{subject_type}/{subject_id}/evaluate",
    response_model=BehavioralAnomalyResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def evaluate_subject_observation(
    subject_type: str,
    subject_id: str,
    payload: EvaluateObservationRequest,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> BehavioralAnomalyResponse:
    """Evaluate an observed metric value against the subject's baseline, recording anomaly if abnormal."""
    svc = BaselineService(db)
    anomaly = svc.evaluate_observation(
        installation_id=installation_id,
        subject_type=subject_type,
        subject_id=subject_id,
        dimension=payload.dimension,
        observed_value=payload.observed_value,
        case_id=payload.case_id,
        historical_samples=payload.historical_samples,
        observation_context=payload.observation_context,
    )
    return BehavioralAnomalyResponse.model_validate(anomaly)


@router.get(
    "/anomalies",
    response_model=list[BehavioralAnomalyResponse],
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR, ROLE_AUDITOR))],
)
def list_behavioral_anomalies(
    subject_id: str | None = Query(None, description="Optional subject ID filter"),
    case_id: str | None = Query(None, description="Optional case ID filter"),
    limit: int = Query(50, ge=1, le=500),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> list[BehavioralAnomalyResponse]:
    """List behavioral anomalies with scoped installation isolation."""
    svc = BaselineService(db)
    records = svc.list_anomalies(
        installation_id=installation_id,
        subject_id=subject_id,
        case_id=case_id,
        limit=limit,
    )
    return [BehavioralAnomalyResponse.model_validate(r) for r in records]


@router.post(
    "/admission/evaluate",
    response_model=BaselineAdmissionResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def evaluate_baseline_admission(
    payload: BaselineAdmissionRequest,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> BaselineAdmissionResponse:
    """Evaluate whether an incoming banking event is eligible for baseline inclusion (poisoning protection)."""
    svc = BaselineService(db)
    record = svc.evaluate_admission(
        installation_id=installation_id,
        event_id=payload.event_id,
        subject_id=payload.subject_id,
        event_is_verified=payload.event_is_verified,
        event_is_under_investigation=payload.event_is_under_investigation,
        event_is_correction=payload.event_is_correction,
        event_is_test_data=payload.event_is_test_data,
        event_is_compromised=payload.event_is_compromised,
    )
    return BaselineAdmissionResponse(
        event_id=record.event_id,
        subject_id=record.subject_id,
        accepted=record.accepted,
        reason=record.reason,
    )


@router.get(
    "/cases/{case_id}/priority",
    response_model=InvestigationPriorityResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR, ROLE_AUDITOR))],
)
def get_case_investigation_priority(
    case_id: str,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> InvestigationPriorityResponse:
    """Calculate explainable operational triage priority for an investigation case."""
    svc = BaselineService(db)
    priority = svc.calculate_case_priority(
        installation_id=installation_id,
        case_id=case_id,
    )
    return InvestigationPriorityResponse(
        priority_score=priority.priority_score,
        reasons=list(priority.reasons),
        requires_review=priority.requires_review,
        independent_sources_count=priority.independent_sources_count,
        unresolved_contradictions=priority.unresolved_contradictions,
    )


@router.get(
    "/governance/methods",
    response_model=list[DetectionMethodResponse],
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR, ROLE_AUDITOR))],
)
def list_governance_detection_methods(
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> list[DetectionMethodResponse]:
    """List registered detection methods, versions, and validation records for model governance."""
    svc = BaselineService(db)
    records = svc.list_detection_methods()
    return [DetectionMethodResponse.model_validate(r) for r in records]
