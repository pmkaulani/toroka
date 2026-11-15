"""Case management endpoints."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from ..auth import EnterprisePrincipal, get_current_principal
from ..dependencies import get_case_service, get_installation_id
from ..schemas import (
    CaseAssignRequest,
    CaseAssignmentResponse,
    CaseCloseRequest,
    CaseDetailResponse,
    CaseIntakeRequest,
    CaseIntakeResponse,
    CaseListResponse,
    CaseSummaryResponse,
    ClosureProposalCreate,
    ClosureProposalResponse,
    NoteCreateRequest,
    NoteResponse,
)
from ..services.cases import CaseService

router = APIRouter(
    prefix="/api/enterprise/v1/cases",
    tags=["Enterprise Casework"],
)


@router.post("/intake", response_model=CaseIntakeResponse, status_code=status.HTTP_201_CREATED)
def intake_cases_from_run(
    req: CaseIntakeRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    case_service: CaseService = Depends(get_case_service),
    installation_id: str = Depends(get_installation_id),
):
    try:
        res = case_service.intake_from_run(
            principal,
            installation_id=installation_id,
            manifest_id=req.manifest_id,
            leads=req.leads,
            assign_to_subject=req.assign_to_subject,
        )
        return CaseIntakeResponse(**res)
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.get("", response_model=CaseListResponse)
def list_cases(
    status_filter: str | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    principal: EnterprisePrincipal = Depends(get_current_principal),
    case_service: CaseService = Depends(get_case_service),
    installation_id: str = Depends(get_installation_id),
):
    try:
        cases, total = case_service.list_cases(
            principal,
            installation_id=installation_id,
            status=status_filter,
            limit=limit,
            offset=offset,
        )
        return CaseListResponse(
            total=total,
            items=[CaseSummaryResponse.model_validate(c) for c in cases],
        )
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))


@router.get("/{case_id}", response_model=CaseDetailResponse)
def get_case(
    case_id: str,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    case_service: CaseService = Depends(get_case_service),
):
    try:
        case = case_service.get_case(principal, case_id)
        return CaseDetailResponse.model_validate(case)
    except LookupError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Case not found")
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))


@router.get("/{case_id}/evidence")
def get_case_evidence(
    case_id: str,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    case_service: CaseService = Depends(get_case_service),
) -> dict[str, Any]:
    try:
        case = case_service.get_case(principal, case_id)
        return {
            "case_id": case.id,
            "snapshot_sha256": case.snapshot_sha256,
            "evidence": case.snapshot,
        }
    except LookupError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Case not found")
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))


@router.get("/{case_id}/notes", response_model=list[NoteResponse])
def list_case_notes(
    case_id: str,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    case_service: CaseService = Depends(get_case_service),
):
    try:
        # Verify access to case first
        case_service.get_case(principal, case_id)
        notes = case_service.notes.list_notes_for_case(case_id)
        return [NoteResponse.model_validate(n) for n in notes]
    except LookupError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Case not found")
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))


@router.post("/{case_id}/notes", response_model=NoteResponse, status_code=status.HTTP_201_CREATED)
def add_case_note(
    case_id: str,
    req: NoteCreateRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    case_service: CaseService = Depends(get_case_service),
):
    try:
        note = case_service.add_note(principal, case_id, req.body)
        return NoteResponse.model_validate(note)
    except LookupError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Case not found")
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post("/{case_id}/assign", response_model=CaseAssignmentResponse)
def assign_case(
    case_id: str,
    req: CaseAssignRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    case_service: CaseService = Depends(get_case_service),
):
    try:
        assignment = case_service.assign_case(
            principal,
            case_id,
            req.assignee_subject,
            req.assignment_role,
        )
        return CaseAssignmentResponse.model_validate(assignment)
    except LookupError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Case not found")
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post("/{case_id}/close", response_model=CaseDetailResponse)
def close_case(
    case_id: str,
    req: CaseCloseRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    case_service: CaseService = Depends(get_case_service),
):
    try:
        case = case_service.close_case(
            principal,
            case_id,
            disposition=req.disposition,
            closing_note=req.closing_note,
            alternatives_considered=req.alternatives_considered,
            expected_version=req.expected_version,
        )
        return CaseDetailResponse.model_validate(case)
    except LookupError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Case not found")
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post(
    "/{case_id}/propose-closure",
    response_model=ClosureProposalResponse,
    status_code=status.HTTP_201_CREATED,
)
def propose_case_closure(
    case_id: str,
    req: ClosureProposalCreate,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    case_service: CaseService = Depends(get_case_service),
):
    try:
        proposal = case_service.propose_closure(
            principal,
            case_id,
            disposition=req.disposition,
            closing_note=req.closing_note,
            alternatives_considered=req.alternatives_considered,
            expected_case_version=req.expected_case_version,
        )
        return ClosureProposalResponse.model_validate(proposal)
    except LookupError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Case not found")
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.get(
    "/{case_id}/closure-proposals",
    response_model=list[ClosureProposalResponse],
)
def list_case_closure_proposals(
    case_id: str,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    case_service: CaseService = Depends(get_case_service),
):
    try:
        proposals = case_service.list_case_closure_proposals(principal, case_id)
        return [ClosureProposalResponse.model_validate(p) for p in proposals]
    except LookupError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Case not found")
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))
