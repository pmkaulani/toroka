"""API router for Phase 10: Network Intelligence & Collaborative Fraud Graphs."""
from __future__ import annotations

import logging
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ..auth import EnterprisePrincipal, get_current_principal, require_roles
from ..dependencies import get_db, get_installation_id
from ..network_schemas import (
    EntityLinkCandidateResponse,
    EntityLinkReviewRequest,
    EntityLinkReviewResponse,
    EvidenceSubgraphResponse,
    FindingEvidenceSubgraphResponse,
    NeighborhoodExpandRequest,
    NetworkAnalysisRequest,
    NetworkAnalysisResponse,
    NetworkAnalysisRunResponse,
    NetworkEdgeResponse,
    NetworkNodeResponse,
    NetworkPatternFindingResponse,
    NetworkSnapshotResponse,
    ShortestPathRequest,
    ShortestPathResponse,
)
from ..permissions import (
    ROLE_AUDITOR,
    ROLE_AUTHORISER,
    ROLE_INVESTIGATOR,
    ROLE_SYSTEM_ADMINISTRATOR,
)
from ..services.network import NetworkService

logger = logging.getLogger(__name__)


def _primary_role(principal: EnterprisePrincipal) -> str:
    return sorted(principal.roles)[0] if principal.roles else "investigator"


router = APIRouter(
    prefix="/api/enterprise/v1/network",
    tags=["Network Intelligence & Fraud Graphs"],
)


@router.post(
    "/analyze",
    response_model=NetworkAnalysisResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def run_network_analysis(
    req: NetworkAnalysisRequest,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> NetworkAnalysisResponse:
    """Run comprehensive network analysis for given seed entities or investigated case."""
    svc = NetworkService(db, principal.installation_id or installation_id)
    return svc.analyze(req, principal.subject, _primary_role(principal))


@router.post(
    "/expand",
    response_model=EvidenceSubgraphResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def expand_neighborhood(
    req: NeighborhoodExpandRequest,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> EvidenceSubgraphResponse:
    """Bounded neighborhood expansion with deterministic traversal and explicit truncation signaling."""
    svc = NetworkService(db, principal.installation_id or installation_id)
    return svc.expand(req, principal.subject, _primary_role(principal))


@router.post(
    "/path",
    response_model=ShortestPathResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def find_shortest_path_endpoint(
    req: ShortestPathRequest,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> ShortestPathResponse:
    """Find the shortest evidence-backed path between two entities in the installation graph."""
    svc = NetworkService(db, principal.installation_id or installation_id)
    return svc.shortest_path(req, principal.subject, _primary_role(principal))


@router.get(
    "/nodes/{node_key}",
    response_model=NetworkNodeResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def get_network_node(
    node_key: str,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> NetworkNodeResponse:
    """Retrieve node details and attributes for an entity key."""
    svc = NetworkService(db, principal.installation_id or installation_id)
    graph = svc.load_active_network()
    node = graph.get_node(node_key)
    if not node:
        raise HTTPException(status_code=404, detail=f"Node '{node_key}' not found in installation network")
    return svc._to_node_response(node)


@router.get(
    "/edges",
    response_model=list[NetworkEdgeResponse],
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def list_network_edges(
    source_key: str | None = None,
    target_key: str | None = None,
    relationship_type: str | None = None,
    include_shared_attributes: bool = False,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> list[NetworkEdgeResponse]:
    """Query network edges with optional source, target, or relationship filtering."""
    svc = NetworkService(db, principal.installation_id or installation_id)
    graph = svc.load_active_network()
    edges = graph.edges
    if source_key:
        edges = [e for e in edges if e.source_key == source_key]
    if target_key:
        edges = [e for e in edges if e.target_key == target_key]
    if relationship_type:
        edges = [e for e in edges if e.relationship_type == relationship_type]
    if not include_shared_attributes:
        edges = [e for e in edges if e.evidence_basis.value != "shared_attribute"]
    return [svc._to_edge_response(e) for e in edges[:200]]


@router.get(
    "/findings",
    response_model=list[NetworkPatternFindingResponse],
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def list_network_findings(
    case_id: str | None = None,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> list[NetworkPatternFindingResponse]:
    """List detected network motifs and pattern findings for the installation or specific case."""
    svc = NetworkService(db, principal.installation_id or installation_id)
    return svc.list_findings(case_id=case_id)


@router.get(
    "/findings/{finding_id}",
    response_model=FindingEvidenceSubgraphResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def get_finding_evidence_subgraph(
    finding_id: str,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> FindingEvidenceSubgraphResponse:
    """Retrieve the compact evidence subgraph and provenance details for a finding."""
    svc = NetworkService(db, principal.installation_id or installation_id)
    return svc.get_finding_evidence(finding_id)


@router.get(
    "/entity-links",
    response_model=list[EntityLinkCandidateResponse],
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def list_entity_link_candidates(
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> list[EntityLinkCandidateResponse]:
    """List proposed entity relationship candidates awaiting or subject to review."""
    svc = NetworkService(db, principal.installation_id or installation_id)
    return svc.list_entity_link_candidates()


@router.post(
    "/entity-links/{candidate_id}/review",
    response_model=EntityLinkReviewResponse,
    dependencies=[Depends(require_roles(ROLE_AUTHORISER, ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def review_entity_link(
    candidate_id: str,
    req: EntityLinkReviewRequest,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> EntityLinkReviewResponse:
    """Submit human review decision for an entity link candidate with auditable justification."""
    svc = NetworkService(db, principal.installation_id or installation_id)
    return svc.review_entity_link(
        candidate_id=candidate_id,
        decision_str=req.decision,
        rationale=req.rationale,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )


@router.get(
    "/snapshots",
    response_model=list[NetworkSnapshotResponse],
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def list_network_snapshots(
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> list[NetworkSnapshotResponse]:
    """List point-in-time network graph snapshots."""
    svc = NetworkService(db, principal.installation_id or installation_id)
    return svc.list_snapshots()


@router.post(
    "/snapshots",
    response_model=NetworkSnapshotResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def create_network_snapshot(
    as_of: str | None = None,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> NetworkSnapshotResponse:
    """Create a point-in-time snapshot of the installation network graph."""
    from datetime import datetime
    as_of_dt = datetime.fromisoformat(as_of) if as_of else None
    svc = NetworkService(db, principal.installation_id or installation_id)
    return svc.create_snapshot(as_of_dt, principal.subject, _primary_role(principal))


@router.get(
    "/runs",
    response_model=list[NetworkAnalysisRunResponse],
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def list_analysis_runs(
    case_id: str | None = None,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> list[NetworkAnalysisRunResponse]:
    """Retrieve historical execution logs of network intelligence analysis runs."""
    svc = NetworkService(db, principal.installation_id or installation_id)
    return svc.list_analysis_runs(case_id=case_id)


@router.get(
    "/cases/{case_id}",
    response_model=EvidenceSubgraphResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def get_case_network(
    case_id: str,
    max_depth: int = Query(default=2, ge=0, le=4),
    max_nodes: int = Query(default=100, ge=1, le=500),
    max_edges: int = Query(default=200, ge=1, le=1000),
    include_shared_attributes: bool = Query(default=False),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
    principal: EnterprisePrincipal = Depends(get_current_principal),
) -> EvidenceSubgraphResponse:
    """Retrieve connected network subgraph for a specific case's focus entity or transactions."""
    svc = NetworkService(db, principal.installation_id or installation_id)
    req = NeighborhoodExpandRequest(
        seed_nodes=[f"account:{case_id}", f"customer:{case_id}", f"case:{case_id}"],
        max_depth=max_depth,
        max_nodes=max_nodes,
        max_edges=max_edges,
        include_shared_attributes=include_shared_attributes,
    )
    return svc.expand(req, principal.subject, _primary_role(principal))
