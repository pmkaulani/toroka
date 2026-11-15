"""Identity reveal request, approval, and consumption endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status

from ..auth import EnterprisePrincipal, get_current_principal
from ..dependencies import get_installation_id, get_reveal_service
from ..persistence.models import utc_now
from ..schemas import (
    RevealConsumeResponse,
    RevealRejectRequest,
    RevealRequestCreate,
    RevealRequestResponse,
)
from ..services.reveals import RevealService

router = APIRouter(
    prefix="/api/enterprise/v1",
    tags=["Enterprise Identity Reveal"],
)


@router.post(
    "/cases/{case_id}/reveal-requests",
    response_model=RevealRequestResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_reveal_request(
    case_id: str,
    req: RevealRequestCreate,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    reveal_service: RevealService = Depends(get_reveal_service),
):
    try:
        reveal_req = reveal_service.request_reveal(
            principal,
            case_id=case_id,
            pseudonym=req.pseudonym,
            reason=req.reason,
            ttl_hours=req.ttl_hours,
        )
        return RevealRequestResponse.model_validate(reveal_req)
    except LookupError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Case not found")
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.get("/reveal-requests", response_model=list[RevealRequestResponse])
def list_pending_reveal_requests(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    principal: EnterprisePrincipal = Depends(get_current_principal),
    reveal_service: RevealService = Depends(get_reveal_service),
    installation_id: str = Depends(get_installation_id),
):
    try:
        requests = reveal_service.list_pending(
            principal,
            installation_id=installation_id,
            limit=limit,
            offset=offset,
        )
        return [RevealRequestResponse.model_validate(r) for r in requests]
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))


@router.post(
    "/reveal-requests/{request_id}/approve",
    response_model=RevealRequestResponse,
)
def approve_reveal_request(
    request_id: str,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    reveal_service: RevealService = Depends(get_reveal_service),
):
    try:
        approved = reveal_service.approve_reveal(principal, request_id=request_id)
        return RevealRequestResponse.model_validate(approved)
    except LookupError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Reveal request not found")
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post(
    "/reveal-requests/{request_id}/reject",
    response_model=RevealRequestResponse,
)
def reject_reveal_request(
    request_id: str,
    req: RevealRejectRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    reveal_service: RevealService = Depends(get_reveal_service),
):
    try:
        rejected = reveal_service.reject_reveal(
            principal,
            request_id=request_id,
            rejection_reason=req.rejection_reason,
        )
        return RevealRequestResponse.model_validate(rejected)
    except LookupError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Reveal request not found")
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post(
    "/reveal-requests/{request_id}/consume",
    response_model=RevealConsumeResponse,
)
def consume_reveal_request(
    request_id: str,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    reveal_service: RevealService = Depends(get_reveal_service),
):
    try:
        plaintext = reveal_service.consume_reveal(principal, request_id=request_id)
        req = reveal_service.reveals.get_by_id(request_id)
        pseudonym = req.pseudonym if req else ""
        return RevealConsumeResponse(
            request_id=request_id,
            pseudonym=pseudonym,
            plaintext_identity=plaintext,
            consumed_at=utc_now(),
        )
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))
