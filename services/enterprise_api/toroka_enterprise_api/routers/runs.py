"""Investigation run manifest endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status

from ..auth import EnterprisePrincipal, get_current_principal
from ..dependencies import get_run_service
from ..schemas import RunDetailResponse, RunSummaryResponse
from ..services.runs import RunService

router = APIRouter(
    prefix="/api/enterprise/v1/runs",
    tags=["Enterprise Runs"],
)


@router.get("", response_model=list[RunSummaryResponse])
def list_runs(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    principal: EnterprisePrincipal = Depends(get_current_principal),
    run_service: RunService = Depends(get_run_service),
):
    try:
        runs = run_service.list_runs(principal, limit=limit, offset=offset)
        return [RunSummaryResponse.model_validate(r) for r in runs]
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))


@router.get("/{manifest_id}", response_model=RunDetailResponse)
def get_run(
    manifest_id: str,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    run_service: RunService = Depends(get_run_service),
):
    try:
        run = run_service.get_run(principal, manifest_id)
        return RunDetailResponse.model_validate(run)
    except LookupError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Run not found")
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))
