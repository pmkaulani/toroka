"""Pydantic schemas for the Attack Reconstruction Engine."""
from __future__ import annotations

from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class ReconstructionStepResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    sequence: int
    event_id: str
    event_type: str
    event_time: datetime
    actor_id: str | None = None
    subject_id: str | None = None
    source_system: str | None = None
    explanation: str
    evidence_strength: float
    provenance_ids: list[str] = Field(default_factory=list)


class StateTransitionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    previous_state: str
    new_state: str
    event_id: str
    explanation: str
    material_change: bool


class ChangeVectorResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    subject_id: str
    changed_dimensions: list[str]
    baseline_dimensions: list[str]
    unusual_dimensions: list[str]
    explanation: str
    completeness: float


class AttackPathNodeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    node_id: str
    node_type: str
    label: str


class AttackPathEdgeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    source_id: str
    target_id: str
    relationship: str
    event_ids: list[str]
    confidence: float


class AttackPathResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    path_id: str
    nodes: list[AttackPathNodeResponse]
    edges: list[AttackPathEdgeResponse]
    confidence: float


class EvidenceContradictionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    contradiction_id: str
    installation_id: str
    case_id: str | None = None
    event_a: str
    event_b: str
    field: str
    value_a: str
    value_b: str
    severity: str
    explanation: str
    resolution_required: bool
    status: str
    resolved_by: str | None = None
    resolution_note: str | None = None
    created_at: datetime
    resolved_at: datetime | None = None


class ResolveContradictionRequest(BaseModel):
    resolution_note: str


class EvidenceCompletenessResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    total_requirements: int
    satisfied_requirements: int
    missing_requirements: list[str]
    percentage: float
    evidence_debt: list[str]


class InvestigationScenarioResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    scenario_id: str
    title: str
    description: str
    required_evidence: list[str]
    supporting_evidence: list[str]
    contradicting_evidence: list[str]
    missing_evidence: list[str]
    relative_support: float


class ReconstructionBundleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    reconstruction_id: str
    installation_id: str
    case_id: str | None = None
    title: str
    start_time: datetime
    end_time: datetime
    steps: list[ReconstructionStepResponse]
    state_transitions: list[StateTransitionResponse]
    change_vector: ChangeVectorResponse | None = None
    attack_path: AttackPathResponse | None = None
    contradictions: list[EvidenceContradictionResponse]
    evidence_completeness: EvidenceCompletenessResponse
    scenarios: list[InvestigationScenarioResponse]
    unresolved_questions: list[str]
    confidence: float
    created_at: datetime
