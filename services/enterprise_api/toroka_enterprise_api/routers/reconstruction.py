"""API router for Attack Reconstruction, state transitions, attack paths, and competing scenarios."""
from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ..auth import EnterprisePrincipal, get_current_principal, require_roles
from ..dependencies import get_db, get_installation_id
from ..reconstruction_schemas import (
    ReconstructionBundleResponse,
    ChangeVectorResponse,
    AttackPathResponse,
    EvidenceContradictionResponse,
    ResolveContradictionRequest,
    InvestigationScenarioResponse,
)
from ..permissions import (
    ROLE_AUDITOR,
    ROLE_AUTHORISER,
    ROLE_INVESTIGATOR,
    ROLE_SYSTEM_ADMINISTRATOR,
)
from ..services.reconstruction import ReconstructionService

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/enterprise/v1/reconstruction",
    tags=["Enterprise Attack Reconstruction Engine"],
)


@router.post(
    "/cases/{case_id}/reconstruct",
    response_model=ReconstructionBundleResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def reconstruct_incident(
    case_id: str,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> ReconstructionBundleResponse:
    """Deterministically reconstructs an incident timeline from independently sourced evidence."""
    svc = ReconstructionService(db, principal.installation_id or installation_id)
    return svc.reconstruct_case(case_id, actor=principal.subject)


@router.get(
    "/cases/{case_id}",
    response_model=ReconstructionBundleResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR, ROLE_AUDITOR))],
)
def get_case_reconstruction(
    case_id: str,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> ReconstructionBundleResponse:
    """Retrieves full attack reconstruction bundle for a case."""
    svc = ReconstructionService(db, principal.installation_id or installation_id)
    return svc.get_case_reconstruction(case_id)


@router.get(
    "/cases/{case_id}/change-vector",
    response_model=ChangeVectorResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR, ROLE_AUDITOR))],
)
def get_case_change_vector(
    case_id: str,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> ChangeVectorResponse:
    """Retrieves subject Change Vector indicating what changed relative to baseline."""
    svc = ReconstructionService(db, principal.installation_id or installation_id)
    recon = svc.get_case_reconstruction(case_id)
    if not recon.change_vector:
        raise HTTPException(status_code=404, detail="Change vector not available for this case")
    return recon.change_vector


@router.get(
    "/cases/{case_id}/attack-path",
    response_model=AttackPathResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR, ROLE_AUDITOR))],
)
def get_case_attack_path(
    case_id: str,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> AttackPathResponse:
    """Retrieves evidence-backed attack path node/edge graph."""
    svc = ReconstructionService(db, principal.installation_id or installation_id)
    recon = svc.get_case_reconstruction(case_id)
    if not recon.attack_path:
        raise HTTPException(status_code=404, detail="Attack path not available for this case")
    return recon.attack_path


@router.get(
    "/cases/{case_id}/contradictions",
    response_model=list[EvidenceContradictionResponse],
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR, ROLE_AUDITOR))],
)
def list_case_contradictions(
    case_id: str,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> list[EvidenceContradictionResponse]:
    """Lists surfaced multi-source evidence contradictions."""
    svc = ReconstructionService(db, principal.installation_id or installation_id)
    recon = svc.get_case_reconstruction(case_id)
    return recon.contradictions


@router.post(
    "/cases/{case_id}/contradictions/{contradiction_id}/resolve",
    response_model=EvidenceContradictionResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def resolve_evidence_contradiction(
    case_id: str,
    contradiction_id: str,
    payload: ResolveContradictionRequest,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> EvidenceContradictionResponse:
    """Investigator resolves a contradiction with rationale."""
    svc = ReconstructionService(db, principal.installation_id or installation_id)
    rec = svc.resolve_contradiction(
        case_id=case_id,
        contradiction_id=contradiction_id,
        resolved_by=principal.subject,
        resolution_note=payload.resolution_note,
    )
    if not rec:
        raise HTTPException(status_code=404, detail="Contradiction not found")
    return EvidenceContradictionResponse.model_validate(rec)


@router.get(
    "/cases/{case_id}/scenarios",
    response_model=list[InvestigationScenarioResponse],
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR, ROLE_AUDITOR))],
)
def list_case_scenarios(
    case_id: str,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> list[InvestigationScenarioResponse]:
    """Retrieves structured competing investigation scenarios."""
    svc = ReconstructionService(db, principal.installation_id or installation_id)
    recon = svc.get_case_reconstruction(case_id)
    return recon.scenarios
