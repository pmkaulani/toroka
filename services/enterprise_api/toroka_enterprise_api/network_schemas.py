"""Pydantic schemas for Phase 10: Network Intelligence & Collaborative Fraud Graphs."""
from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class NetworkNodeResponse(BaseModel):
    installation_id: str
    node_key: str
    entity_type: str
    pseudonymous_label: str
    attributes: dict[str, Any] = Field(default_factory=dict)
    first_seen: str | None = None
    last_seen: str | None = None


class NetworkEdgeResponse(BaseModel):
    installation_id: str
    edge_id: str
    source_key: str
    target_key: str
    relationship_type: str
    evidence_basis: str
    event_ids: list[str] = Field(default_factory=list)
    source_record_ids: list[str] = Field(default_factory=list)
    source_systems: list[str] = Field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    confidence: float
    directed: bool
    attributes: dict[str, Any] = Field(default_factory=dict)


class EvidenceSubgraphResponse(BaseModel):
    installation_id: str
    seed_nodes: list[str]
    nodes: list[NetworkNodeResponse]
    edges: list[NetworkEdgeResponse]
    truncated: bool
    truncation_reason: str | None = None
    max_depth_reached: int
    limitations: list[str] = Field(default_factory=list)
    node_count: int
    edge_count: int


class NeighborhoodExpandRequest(BaseModel):
    seed_nodes: list[str] = Field(..., min_length=1, max_length=50)
    max_depth: int = Field(default=2, ge=0, le=4)
    max_nodes: int = Field(default=100, ge=1, le=500)
    max_edges: int = Field(default=200, ge=1, le=1000)
    minimum_confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    include_shared_attributes: bool = Field(default=False)
    direction: str = Field(default="both")
    as_of: str | None = None


class ShortestPathRequest(BaseModel):
    source_key: str = Field(..., min_length=1)
    target_key: str = Field(..., min_length=1)
    max_depth: int = Field(default=5, ge=1, le=8)
    minimum_confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    include_shared_attributes: bool = Field(default=False)


class ShortestPathResponse(BaseModel):
    source_key: str
    target_key: str
    found: bool
    path_length: int
    nodes: list[NetworkNodeResponse] = Field(default_factory=list)
    edges: list[NetworkEdgeResponse] = Field(default_factory=list)


class NetworkAnalysisRequest(BaseModel):
    seed_entities: list[str] = Field(..., min_length=1, max_length=50)
    case_id: str | None = None
    max_depth: int = Field(default=2, ge=0, le=4)
    max_nodes: int = Field(default=100, ge=1, le=500)
    max_edges: int = Field(default=200, ge=1, le=1000)
    include_shared_attributes: bool = Field(default=False)
    as_of: str | None = None


class NetworkPatternFindingResponse(BaseModel):
    pattern_id: str
    installation_id: str
    pattern_type: str
    anchor_entity: str
    related_entities: list[str]
    event_ids: list[str]
    start_time: str
    end_time: str
    detection_time: str
    explanation: str
    evidence_limitations: list[str]
    alternative_legitimate_explanations: list[str]
    supporting_source_systems: list[str]
    transaction_ids: list[str]
    monetary_total: str | None = None
    currency: str | None = None
    confidence: float
    pattern_version: str


class EntityLinkCandidateResponse(BaseModel):
    candidate_id: str
    installation_id: str
    source_entity_key: str
    target_entity_key: str
    attribute_type: str
    attribute_value: str
    match_type: str
    status: str
    confidence: float
    supporting_evidence: list[dict[str, Any]]
    contradicting_evidence: list[dict[str, Any]]
    source_systems: list[str]
    first_observed: str
    last_observed: str
    reviewed_by: str | None = None
    reviewed_at: str | None = None
    review_rationale: str | None = None


class EntityLinkReviewRequest(BaseModel):
    decision: str = Field(..., description="SAME_ENTITY_CONFIRMED, POSSIBLY_RELATED, SHARED_ATTRIBUTE_ONLY, or RELATIONSHIP_DISPROVEN")
    rationale: str = Field(..., min_length=5, description="Clear, substantive justification for the review decision")


class EntityLinkReviewResponse(BaseModel):
    review_id: str
    candidate_id: str
    installation_id: str
    reviewer_subject: str
    decision: str
    rationale: str
    previous_status: str
    new_status: str
    reviewed_at: str


class FindingEvidenceSubgraphResponse(BaseModel):
    finding_id: str
    installation_id: str
    pattern_type: str
    anchor_entity: str
    nodes: list[NetworkNodeResponse]
    edges: list[NetworkEdgeResponse]
    supporting_event_ids: list[str]
    supporting_transaction_ids: list[str]
    supporting_source_systems: list[str]
    confidence: float
    explanation: str
    limitations: list[str]
    alternative_explanations: list[str]
    missing_information: list[str]


class NetworkAnalysisResponse(BaseModel):
    analysis_id: str
    installation_id: str
    case_id: str | None = None
    anchor_entities: list[str]
    subgraph: EvidenceSubgraphResponse
    findings: list[NetworkPatternFindingResponse]
    entity_link_candidates: list[EntityLinkCandidateResponse]
    source_coverage: float
    source_systems: list[str]
    alternative_explanations: list[str]
    missing_evidence: list[str]
    institutional_pattern_matches: list[dict[str, Any]]
    executed_at: str


class NetworkSnapshotResponse(BaseModel):
    snapshot_id: str
    installation_id: str
    as_of: str
    node_count: int
    edge_count: int
    nodes_digest: str
    edges_digest: str
    metadata: dict[str, Any]
    created_at: str


class NetworkAnalysisRunResponse(BaseModel):
    run_id: str
    installation_id: str
    case_id: str | None = None
    executed_by: str
    seed_entities: list[str]
    findings_count: int
    nodes_count: int
    edges_count: int
    truncated: bool
    result_digest: str
    executed_at: str
