"""Governance, maker-checker closure review, workbench overview, and audit verification endpoints."""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..auth import EnterprisePrincipal, get_current_principal
from ..dependencies import (
    get_case_service,
    get_db,
    get_installation_id,
    get_reveal_service,
    get_run_service,
)
from ..permissions import (
    CASEWORK_ROLES,
    ROLE_AUDITOR,
    ROLE_AUTHORISER,
    ROLE_DATA_STEWARD,
    ROLE_INVESTIGATOR,
    ROLE_SYSTEM_ADMINISTRATOR,
)
from ..persistence.audit import verify_audit_chain
from ..persistence.checkpoints import AuditCheckpointManager
from ..persistence.models import (
    AuditRecord,
    CaseAssignment,
    CaseClosureProposal,
    EnterpriseCase,
    RevealRequest,
    RunRecord,
)
from ..schemas import (
    AuditCheckpointResponse,
    AuditCheckpointVerifyResponse,
    AuditTimelineItemResponse,
    AuditVerificationResponse,
    ClosureProposalResponse,
    ClosureReviewRequest,
    WorkbenchOverviewResponse,
)
from ..services.cases import CaseService, resolve_installation_id
from ..services.reveals import RevealService
from ..services.runs import RunService

router = APIRouter(
    prefix="/api/enterprise/v1",
    tags=["Enterprise Governance"],
)


@router.get("/closure-proposals", response_model=list[ClosureProposalResponse])
def list_pending_closure_proposals(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    principal: EnterprisePrincipal = Depends(get_current_principal),
    case_service: CaseService = Depends(get_case_service),
    installation_id: str = Depends(get_installation_id),
):
    try:
        proposals = case_service.list_pending_closure_proposals(
            principal, installation_id, limit=limit, offset=offset
        )
        return [ClosureProposalResponse.model_validate(p) for p in proposals]
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))


@router.post(
    "/closure-proposals/{proposal_id}/review",
    response_model=ClosureProposalResponse,
)
def review_closure_proposal(
    proposal_id: str,
    req: ClosureReviewRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    case_service: CaseService = Depends(get_case_service),
):
    try:
        proposal = case_service.review_closure(
            principal,
            proposal_id,
            approve=req.approve,
            review_note=req.review_note,
        )
        return ClosureProposalResponse.model_validate(proposal)
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.get("/overview", response_model=WorkbenchOverviewResponse)
def get_workbench_overview(
    principal: EnterprisePrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    installation_id: str = Depends(get_installation_id),
):
    # Determine primary role for display
    role = "viewer"
    for r in [
        ROLE_INVESTIGATOR,
        ROLE_AUTHORISER,
        ROLE_AUDITOR,
        ROLE_DATA_STEWARD,
        ROLE_SYSTEM_ADMINISTRATOR,
    ]:
        if r in principal.roles:
            role = r
            break

    # If data steward, they only see contract and ingestion stats; no case counts
    if role == ROLE_DATA_STEWARD and not principal.roles.intersection(CASEWORK_ROLES):
        run_count = db.execute(
            select(func.count(RunRecord.id)).where(RunRecord.installation_id == installation_id)
        ).scalar() or 0
        return WorkbenchOverviewResponse(
            role=role,
            installation_id=installation_id,
            open_cases_count=0,
            closed_cases_count=0,
            assigned_cases_count=0,
            pending_reveals_count=0,
            pending_closures_count=0,
            recent_runs_count=run_count,
            audit_records_count=0,
            contract_version="2.0.0",
        )

    # General casework overview
    open_cases = db.execute(
        select(func.count(EnterpriseCase.id)).where(
            EnterpriseCase.installation_id == installation_id,
            EnterpriseCase.status == "open",
        )
    ).scalar() or 0

    closed_cases = db.execute(
        select(func.count(EnterpriseCase.id)).where(
            EnterpriseCase.installation_id == installation_id,
            EnterpriseCase.status == "closed",
        )
    ).scalar() or 0

    assigned_cases = db.execute(
        select(func.count(CaseAssignment.id))
        .join(EnterpriseCase, CaseAssignment.case_id == EnterpriseCase.id)
        .where(
            EnterpriseCase.installation_id == installation_id,
            CaseAssignment.assigned_subject == principal.subject,
            CaseAssignment.status == "active",
        )
    ).scalar() or 0

    pending_reveals = db.execute(
        select(func.count(RevealRequest.id))
        .join(EnterpriseCase, RevealRequest.case_id == EnterpriseCase.id)
        .where(
            EnterpriseCase.installation_id == installation_id,
            RevealRequest.status == "pending",
        )
    ).scalar() or 0

    pending_closures = db.execute(
        select(func.count(CaseClosureProposal.id))
        .join(EnterpriseCase, CaseClosureProposal.case_id == EnterpriseCase.id)
        .where(
            EnterpriseCase.installation_id == installation_id,
            CaseClosureProposal.status == "pending",
        )
    ).scalar() or 0

    run_count = db.execute(
        select(func.count(RunRecord.id)).where(RunRecord.installation_id == installation_id)
    ).scalar() or 0

    audit_count = db.execute(
        select(func.count(AuditRecord.sequence)).where(
            AuditRecord.installation_id == installation_id
        )
    ).scalar() or 0

    return WorkbenchOverviewResponse(
        role=role,
        installation_id=installation_id,
        open_cases_count=open_cases,
        closed_cases_count=closed_cases,
        assigned_cases_count=assigned_cases,
        pending_reveals_count=pending_reveals,
        pending_closures_count=pending_closures,
        recent_runs_count=run_count,
        audit_records_count=audit_count,
        contract_version="2.0.0",
    )


@router.get("/cases/{case_id}/timeline", response_model=list[AuditTimelineItemResponse])
def get_case_timeline(
    case_id: str,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    case_service: CaseService = Depends(get_case_service),
    db: Session = Depends(get_db),
):
    try:
        case = case_service.get_case(principal, case_id)
    except LookupError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Case not found")
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))

    # Query all audit events for this case
    records = db.execute(
        select(AuditRecord)
        .where(AuditRecord.installation_id == case.installation_id)
        .order_by(AuditRecord.sequence.desc())
        .limit(200)
    ).scalars().all()

    timeline = []
    for r in records:
        meta_case_id = r.safe_metadata.get("case_id") if isinstance(r.safe_metadata, dict) else None
        if r.target_id == case_id or meta_case_id == case_id:
            timeline.append(
                AuditTimelineItemResponse(
                    sequence=r.sequence,
                    event_id=r.event_id,
                    action=r.action,
                    actor_subject=r.actor_subject,
                    actor_role=r.actor_role,
                    target_type=r.target_type,
                    target_id=r.target_id,
                    safe_metadata=r.safe_metadata,
                    created_at=r.created_at,
                )
            )

    return timeline


def _require_audit_role(principal: EnterprisePrincipal) -> None:
    if not principal.roles.intersection(
        {ROLE_AUDITOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR}
    ):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="Access to audit operations is restricted to auditors, authorisers, and system administrators.",
        )


def _get_checkpoint_runtime(request: Request):
    store = getattr(request.app.state, "checkpoint_store", None)
    signer = getattr(request.app.state, "checkpoint_signer", None)
    verifier = getattr(request.app.state, "checkpoint_verifier", None)
    if store is None or signer is None or verifier is None:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Audit checkpointing is not configured on this installation.",
        )
    return store, signer, verifier


@router.get("/audit/verify", response_model=AuditVerificationResponse)
def verify_audit_log(
    principal: EnterprisePrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    installation_id: str = Depends(get_installation_id),
):
    _require_audit_role(principal)
    try:
        effective_inst = resolve_installation_id(principal, installation_id)
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))

    is_valid, head_hash, count = verify_audit_chain(db, effective_inst)
    return AuditVerificationResponse(
        installation_id=effective_inst,
        valid=is_valid,
        head_hash=head_hash,
        records_verified=count,
        error=None if is_valid else "Audit hash chain verification failed or chain integrity broken.",
    )


@router.get("/audit/records", response_model=list[AuditTimelineItemResponse])
def list_audit_records(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    principal: EnterprisePrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    installation_id: str = Depends(get_installation_id),
):
    _require_audit_role(principal)
    try:
        effective_inst = resolve_installation_id(principal, installation_id)
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))

    records = db.execute(
        select(AuditRecord)
        .where(AuditRecord.installation_id == effective_inst)
        .order_by(AuditRecord.sequence.desc())
        .limit(limit)
        .offset(offset)
    ).scalars().all()

    return [
        AuditTimelineItemResponse(
            sequence=r.sequence,
            event_id=r.event_id,
            action=r.action,
            actor_subject=r.actor_subject,
            actor_role=r.actor_role,
            target_type=r.target_type,
            target_id=r.target_id,
            safe_metadata=r.safe_metadata,
            created_at=r.created_at,
        )
        for r in records
    ]


@router.post(
    "/audit/checkpoints",
    response_model=AuditCheckpointResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_audit_checkpoint(
    request: Request,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    installation_id: str = Depends(get_installation_id),
):
    """Create, sign, and immutably store an external audit chain checkpoint."""
    _require_audit_role(principal)
    store, signer, _ = _get_checkpoint_runtime(request)
    try:
        effective_inst = resolve_installation_id(principal, installation_id)
        envelope = AuditCheckpointManager.create_checkpoint(effective_inst, db, signer, store)
        return AuditCheckpointResponse(**envelope)
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc))
    except FileExistsError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.get("/audit/checkpoints", response_model=list[str])
def list_audit_checkpoints(
    request: Request,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
):
    """List immutable checkpoint keys stored for this installation."""
    _require_audit_role(principal)
    store, _, _ = _get_checkpoint_runtime(request)
    try:
        effective_inst = resolve_installation_id(principal, installation_id)
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))
    return store.list_keys(prefix=f"checkpoints/{effective_inst}/")


@router.post("/audit/checkpoints/verify", response_model=AuditCheckpointVerifyResponse)
def verify_audit_checkpoint(
    request: Request,
    envelope: AuditCheckpointResponse | None = Body(default=None),
    principal: EnterprisePrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
    installation_id: str = Depends(get_installation_id),
):
    """Verify a signed audit checkpoint (or latest stored checkpoint) against the database."""
    _require_audit_role(principal)
    store, _, verifier = _get_checkpoint_runtime(request)
    try:
        effective_inst = resolve_installation_id(principal, installation_id)
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))

    if envelope is not None:
        raw_envelope = envelope.model_dump()
    else:
        keys = store.list_keys(prefix=f"checkpoints/{effective_inst}/")
        if not keys:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No audit checkpoints stored for this installation.")
        raw_bytes = store.get(keys[-1])
        if raw_bytes is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Stored audit checkpoint is unavailable.")
        raw_envelope = json.loads(raw_bytes.decode("utf-8"))

    ckpt_inst = (raw_envelope.get("data") or {}).get("installation_id")
    if ckpt_inst != effective_inst:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Checkpoint installation does not match active installation.")

    valid, message = AuditCheckpointManager.verify_checkpoint(raw_envelope, verifier, db)
    head_seq = (raw_envelope.get("data") or {}).get("head_sequence")
    return AuditCheckpointVerifyResponse(
        valid=valid,
        message=message,
        head_sequence=head_seq if isinstance(head_seq, int) else None,
    )
