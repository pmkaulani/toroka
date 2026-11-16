"""API router for Counterfactual Investigation Simulator, strategies, ground truth, and dual approvals."""
from __future__ import annotations

import logging
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
from ..services.simulation import SimulationService
from ..simulation_schemas import (
    CaseOutcomeCreate,
    CaseOutcomeResponse,
    SimulationApprovalRequestCreate,
    SimulationApprovalResponse,
    SimulationApprovalReviewCreate,
    SimulationRunRequest,
    SimulationRunResponse,
    SimulationStrategyCreate,
    SimulationStrategyResponse,
)

logger = logging.getLogger(__name__)


def _primary_role(principal: EnterprisePrincipal) -> str:
    return sorted(principal.roles)[0] if principal.roles else "investigator"


router = APIRouter(
    prefix="/api/enterprise/v1/simulation",
    tags=["Counterfactual Investigation Simulator"],
)


@router.post(
    "/strategies",
    response_model=SimulationStrategyResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def create_strategy_version(
    payload: SimulationStrategyCreate,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> SimulationStrategyResponse:
    """Create a new version of an immutable detection strategy."""
    svc = SimulationService(db, principal.installation_id or installation_id)
    rec = svc.create_strategy(payload, principal.subject, _primary_role(principal))
    return SimulationStrategyResponse(
        strategy_id=rec.strategy_id,
        version=rec.version,
        installation_id=rec.installation_id,
        title=rec.title,
        description=rec.description,
        rules_enabled=list(rec.rules_enabled or []),
        parameters=dict(rec.parameters or {}),
        min_severity=rec.min_severity,
        min_confidence=rec.min_confidence,
        status=rec.status,
        created_by=rec.created_by,
        created_at=rec.created_at.isoformat(),
    )


@router.get(
    "/strategies",
    response_model=list[SimulationStrategyResponse],
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def list_strategies(
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> list[SimulationStrategyResponse]:
    """List all simulation strategies and versions in this installation."""
    svc = SimulationService(db, principal.installation_id or installation_id)
    records = svc.list_strategies()
    return [
        SimulationStrategyResponse(
            strategy_id=r.strategy_id,
            version=r.version,
            installation_id=r.installation_id,
            title=r.title,
            description=r.description,
            rules_enabled=list(r.rules_enabled or []),
            parameters=dict(r.parameters or {}),
            min_severity=r.min_severity,
            min_confidence=r.min_confidence,
            status=r.status,
            created_by=r.created_by,
            created_at=r.created_at.isoformat(),
        )
        for r in records
    ]


@router.get(
    "/strategies/{strategy_id}",
    response_model=SimulationStrategyResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def get_strategy(
    strategy_id: str,
    version: int | None = Query(None, description="Specific version; defaults to latest"),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> SimulationStrategyResponse:
    """Retrieve strategy definition by ID and version."""
    svc = SimulationService(db, principal.installation_id or installation_id)
    r = svc.get_strategy(strategy_id, version)
    return SimulationStrategyResponse(
        strategy_id=r.strategy_id,
        version=r.version,
        installation_id=r.installation_id,
        title=r.title,
        description=r.description,
        rules_enabled=list(r.rules_enabled or []),
        parameters=dict(r.parameters or {}),
        min_severity=r.min_severity,
        min_confidence=r.min_confidence,
        status=r.status,
        created_by=r.created_by,
        created_at=r.created_at.isoformat(),
    )


@router.post(
    "/labels",
    response_model=CaseOutcomeResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def adjudicate_case_outcome(
    payload: CaseOutcomeCreate,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> CaseOutcomeResponse:
    """Adjudicate the historical ground truth outcome for a case."""
    svc = SimulationService(db, principal.installation_id or installation_id)
    rec = svc.adjudicate_case_outcome(payload, principal.subject, _primary_role(principal))
    return CaseOutcomeResponse(
        case_id=rec.case_id,
        installation_id=rec.installation_id,
        label=rec.label,
        first_fraud_event_time=rec.first_fraud_event_time.isoformat() if rec.first_fraud_event_time else None,
        adjudicated_at=rec.adjudicated_at.isoformat(),
        adjudicated_by=rec.adjudicated_by,
        notes=rec.notes,
    )


@router.get(
    "/labels",
    response_model=list[CaseOutcomeResponse],
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def list_case_outcomes(
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> list[CaseOutcomeResponse]:
    """List all ground truth adjudicated case outcomes in this installation."""
    svc = SimulationService(db, principal.installation_id or installation_id)
    records = svc.list_case_outcomes()
    return [
        CaseOutcomeResponse(
            case_id=r.case_id,
            installation_id=r.installation_id,
            label=r.label,
            first_fraud_event_time=r.first_fraud_event_time.isoformat() if r.first_fraud_event_time else None,
            adjudicated_at=r.adjudicated_at.isoformat(),
            adjudicated_by=r.adjudicated_by,
            notes=r.notes,
        )
        for r in records
    ]


@router.post(
    "/runs",
    response_model=SimulationRunResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def execute_simulation_run(
    payload: SimulationRunRequest,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> SimulationRunResponse:
    """Execute counterfactual historical replay for a strategy against historical ground truth."""
    svc = SimulationService(db, principal.installation_id or installation_id)
    rec = svc.run_simulation(payload, principal.subject, _primary_role(principal))
    return SimulationRunResponse(
        simulation_id=rec.simulation_id,
        installation_id=rec.installation_id,
        strategy_id=rec.strategy_id,
        strategy_version=rec.strategy_version,
        baseline_strategy_id=rec.baseline_strategy_id,
        baseline_strategy_version=rec.baseline_strategy_version,
        executed_by=rec.executed_by,
        executed_at=rec.executed_at.isoformat(),
        simulation_cutoff=rec.simulation_cutoff.isoformat() if rec.simulation_cutoff else None,
        metrics=dict(rec.metrics or {}),
        baseline_metrics=dict(rec.baseline_metrics) if rec.baseline_metrics else None,
        delta=dict(rec.delta) if rec.delta else None,
        total_events_replayed=rec.total_events_replayed,
        delayed_events_filtered=rec.delayed_events_filtered,
        case_detections=dict(rec.case_detections or {}),
    )


@router.get(
    "/runs",
    response_model=list[SimulationRunResponse],
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def list_simulation_runs(
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> list[SimulationRunResponse]:
    """List historical simulation runs in this installation."""
    svc = SimulationService(db, principal.installation_id or installation_id)
    records = svc.list_simulation_runs()
    return [
        SimulationRunResponse(
            simulation_id=r.simulation_id,
            installation_id=r.installation_id,
            strategy_id=r.strategy_id,
            strategy_version=r.strategy_version,
            baseline_strategy_id=r.baseline_strategy_id,
            baseline_strategy_version=r.baseline_strategy_version,
            executed_by=r.executed_by,
            executed_at=r.executed_at.isoformat(),
            simulation_cutoff=r.simulation_cutoff.isoformat() if r.simulation_cutoff else None,
            metrics=dict(r.metrics or {}),
            baseline_metrics=dict(r.baseline_metrics) if r.baseline_metrics else None,
            delta=dict(r.delta) if r.delta else None,
            total_events_replayed=r.total_events_replayed,
            delayed_events_filtered=r.delayed_events_filtered,
            case_detections=dict(r.case_detections or {}),
        )
        for r in records
    ]


@router.get(
    "/runs/{simulation_id}",
    response_model=SimulationRunResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def get_simulation_run(
    simulation_id: str,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> SimulationRunResponse:
    """Retrieve full result of a specific simulation run."""
    svc = SimulationService(db, principal.installation_id or installation_id)
    r = svc.get_simulation_run(simulation_id)
    return SimulationRunResponse(
        simulation_id=r.simulation_id,
        installation_id=r.installation_id,
        strategy_id=r.strategy_id,
        strategy_version=r.strategy_version,
        baseline_strategy_id=r.baseline_strategy_id,
        baseline_strategy_version=r.baseline_strategy_version,
        executed_by=r.executed_by,
        executed_at=r.executed_at.isoformat(),
        simulation_cutoff=r.simulation_cutoff.isoformat() if r.simulation_cutoff else None,
        metrics=dict(r.metrics or {}),
        baseline_metrics=dict(r.baseline_metrics) if r.baseline_metrics else None,
        delta=dict(r.delta) if r.delta else None,
        total_events_replayed=r.total_events_replayed,
        delayed_events_filtered=r.delayed_events_filtered,
        case_detections=dict(r.case_detections or {}),
    )


@router.post(
    "/approvals/request",
    response_model=SimulationApprovalResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def request_strategy_approval(
    payload: SimulationApprovalRequestCreate,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> SimulationApprovalResponse:
    """Submit a strategy version for promotion / shadow deployment review."""
    svc = SimulationService(db, principal.installation_id or installation_id)
    rec = svc.request_approval(payload, principal.subject, _primary_role(principal))
    return SimulationApprovalResponse(
        approval_id=rec.approval_id,
        installation_id=rec.installation_id,
        strategy_id=rec.strategy_id,
        strategy_version=rec.strategy_version,
        requester_subject=rec.requester_subject,
        requested_at=rec.requested_at.isoformat(),
        request_rationale=rec.request_rationale,
        simulation_run_id=rec.simulation_run_id,
        status=rec.status,
        reviewer_subject=rec.reviewer_subject,
        reviewed_at=rec.reviewed_at.isoformat() if rec.reviewed_at else None,
        review_decision=rec.review_decision,
        review_notes=rec.review_notes,
    )


@router.post(
    "/approvals/{approval_id}/review",
    response_model=SimulationApprovalResponse,
    dependencies=[Depends(require_roles(ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def review_strategy_approval(
    approval_id: str,
    payload: SimulationApprovalReviewCreate,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> SimulationApprovalResponse:
    """Review and approve or reject a strategy promotion under dual control (requester != reviewer)."""
    svc = SimulationService(db, principal.installation_id or installation_id)
    rec = svc.review_approval(approval_id, payload, principal.subject, _primary_role(principal))
    return SimulationApprovalResponse(
        approval_id=rec.approval_id,
        installation_id=rec.installation_id,
        strategy_id=rec.strategy_id,
        strategy_version=rec.strategy_version,
        requester_subject=rec.requester_subject,
        requested_at=rec.requested_at.isoformat(),
        request_rationale=rec.request_rationale,
        simulation_run_id=rec.simulation_run_id,
        status=rec.status,
        reviewer_subject=rec.reviewer_subject,
        reviewed_at=rec.reviewed_at.isoformat() if rec.reviewed_at else None,
        review_decision=rec.review_decision,
        review_notes=rec.review_notes,
    )


@router.get(
    "/approvals",
    response_model=list[SimulationApprovalResponse],
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def list_strategy_approvals(
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> list[SimulationApprovalResponse]:
    """List all strategy promotion review requests."""
    svc = SimulationService(db, principal.installation_id or installation_id)
    records = svc.list_approvals()
    return [
        SimulationApprovalResponse(
            approval_id=r.approval_id,
            installation_id=r.installation_id,
            strategy_id=r.strategy_id,
            strategy_version=r.strategy_version,
            requester_subject=r.requester_subject,
            requested_at=r.requested_at.isoformat(),
            request_rationale=r.request_rationale,
            simulation_run_id=r.simulation_run_id,
            status=r.status,
            reviewer_subject=r.reviewer_subject,
            reviewed_at=r.reviewed_at.isoformat() if r.reviewed_at else None,
            review_decision=r.review_decision,
            review_notes=r.review_notes,
        )
        for r in records
    ]
