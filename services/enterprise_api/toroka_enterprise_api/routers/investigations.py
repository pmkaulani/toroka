"""Investigation intelligence and referral pack endpoints for Toroka Enterprise."""
from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from toroka_enterprise.investigation.contracts import (
    EntityIn,
    EntityOut,
    EvidenceArtifactIn,
    EvidenceArtifactOut,
    FindingOut,
    GraphQueryResponse,
    RelationshipIn,
    RelationshipOut,
    TimelineResponse,
    TransactionEventIn,
    TransactionEventOut,
)
from ..auth import EnterprisePrincipal, get_current_principal
from ..dependencies import get_installation_id, get_investigation_service
from ..services.investigations import InvestigationService

router = APIRouter(
    prefix="/api/enterprise/v1",
    tags=["Enterprise Investigation Intelligence"],
)


class ReferralPackPreviewRequest(BaseModel):
    recipient_org: str = Field(min_length=2, max_length=200)
    purpose: str = Field(min_length=5, max_length=500)
    legal_basis: str = Field(min_length=5, max_length=500)


class ReferralPackApproveRequest(BaseModel):
    pack_id: str = Field(min_length=32, max_length=36)
    expected_pack_hash: str = Field(pattern=r"^[a-fA-F0-9]{64}$")


# --- Evidence & Entity Management ---
@router.post("/cases/{case_id}/intelligence/evidence", response_model=EvidenceArtifactOut, status_code=status.HTTP_201_CREATED)
def add_case_evidence(
    case_id: str,
    payload: EvidenceArtifactIn,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    service: InvestigationService = Depends(get_investigation_service),
    installation_id: str = Depends(get_installation_id),
):
    try:
        return service.add_evidence(principal, installation_id, case_id, payload)
    except LookupError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(e))
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/cases/{case_id}/intelligence/entities", response_model=EntityOut, status_code=status.HTTP_201_CREATED)
def add_case_entity(
    case_id: str,
    payload: EntityIn,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    service: InvestigationService = Depends(get_investigation_service),
    installation_id: str = Depends(get_installation_id),
):
    try:
        return service.add_entity(principal, installation_id, case_id, payload)
    except LookupError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(e))
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/cases/{case_id}/intelligence/relationships", response_model=RelationshipOut, status_code=status.HTTP_201_CREATED)
def add_case_relationship(
    case_id: str,
    payload: RelationshipIn,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    service: InvestigationService = Depends(get_investigation_service),
    installation_id: str = Depends(get_installation_id),
):
    try:
        return service.add_relationship(principal, installation_id, case_id, payload)
    except LookupError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(e))
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/cases/{case_id}/intelligence/transactions", response_model=TransactionEventOut, status_code=status.HTTP_201_CREATED)
def add_case_transaction(
    case_id: str,
    payload: TransactionEventIn,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    service: InvestigationService = Depends(get_investigation_service),
    installation_id: str = Depends(get_installation_id),
):
    try:
        return service.add_transaction(principal, installation_id, case_id, payload)
    except LookupError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(e))
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(e))


# --- Investigation Intelligence & Analysis ---
@router.get("/cases/{case_id}/intelligence/graph", response_model=GraphQueryResponse)
def get_case_graph(
    case_id: str,
    max_hops: int = Query(3, ge=1, le=10),
    max_nodes: int = Query(50, ge=1, le=200),
    principal: EnterprisePrincipal = Depends(get_current_principal),
    service: InvestigationService = Depends(get_investigation_service),
    installation_id: str = Depends(get_installation_id),
):
    try:
        return service.get_case_graph(installation_id, case_id, max_hops=max_hops, max_nodes=max_nodes)
    except LookupError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/cases/{case_id}/intelligence/findings/run", response_model=list[FindingOut])
def run_case_findings(
    case_id: str,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    service: InvestigationService = Depends(get_investigation_service),
    installation_id: str = Depends(get_installation_id),
):
    try:
        return service.run_findings(principal, installation_id, case_id)
    except LookupError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/cases/{case_id}/intelligence/timeline", response_model=TimelineResponse)
def get_case_timeline(
    case_id: str,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    service: InvestigationService = Depends(get_investigation_service),
    installation_id: str = Depends(get_installation_id),
):
    try:
        return service.get_timeline(installation_id, case_id)
    except LookupError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/cases/{case_id}/intelligence/money-flow")
def get_case_money_flow(
    case_id: str,
    root_entity_id: UUID = Query(...),
    max_hops: int = Query(5, ge=1, le=15),
    max_nodes: int = Query(50, ge=1, le=200),
    principal: EnterprisePrincipal = Depends(get_current_principal),
    service: InvestigationService = Depends(get_investigation_service),
    installation_id: str = Depends(get_installation_id),
):
    try:
        return service.get_money_flow(
            installation_id=installation_id,
            case_id=case_id,
            root_entity_id=root_entity_id,
            max_hops=max_hops,
            max_nodes=max_nodes,
        )
    except LookupError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(e))


# --- Referral Packs ---
@router.post("/cases/{case_id}/referral-packs/preview")
def preview_referral_pack(
    case_id: str,
    payload: ReferralPackPreviewRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    service: InvestigationService = Depends(get_investigation_service),
    installation_id: str = Depends(get_installation_id),
):
    try:
        return service.preview_referral_pack(
            principal=principal,
            installation_id=installation_id,
            case_id=case_id,
            recipient_org=payload.recipient_org,
            purpose=payload.purpose,
            legal_basis=payload.legal_basis,
        )
    except LookupError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(e))
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/cases/{case_id}/referral-packs")
def approve_referral_pack(
    case_id: str,
    payload: ReferralPackApproveRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    service: InvestigationService = Depends(get_investigation_service),
    installation_id: str = Depends(get_installation_id),
):
    try:
        return service.approve_referral_pack(
            principal=principal,
            installation_id=installation_id,
            case_id=case_id,
            pack_id=payload.pack_id,
            expected_pack_hash=payload.expected_pack_hash,
        )
    except LookupError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/referral-packs/{pack_id}")
def get_referral_pack(
    pack_id: str,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    service: InvestigationService = Depends(get_investigation_service),
    installation_id: str = Depends(get_installation_id),
):
    try:
        return service.get_referral_pack(installation_id=installation_id, pack_id=pack_id)
    except LookupError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(e))
