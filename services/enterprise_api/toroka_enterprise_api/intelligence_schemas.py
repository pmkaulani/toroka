"""Pydantic schemas for cross-system fraud intelligence, correlation signals, hypotheses, and bundles."""
from __future__ import annotations

from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field


class IntelligenceEventResponse(BaseModel):
    event_id: str
    installation_id: str
    event_type: str
    event_time: datetime
    actor: str | None = None
    subject: str | None = None
    source_system: str | None = None
    source_record_id: str | None = None
    entities: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)
    provenance_digest: str | None = None


class EntityRefSchema(BaseModel):
    installation_id: str
    entity_type: str
    entity_id: str
    display_id: str | None = None


class RelationshipResponse(BaseModel):
    id: str | None = None
    installation_id: str
    source_type: str
    source_id: str
    target_type: str
    target_id: str
    relationship_type: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    confidence: float
    source_system: str | None = None
    source_record_id: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class CorrelationSignalResponse(BaseModel):
    signal_id: str
    signal_type: str
    severity: str
    title: str
    explanation: str
    event_ids: list[str]
    confidence: float
    evidence: list[dict[str, Any]]
    alternative_explanations: list[str]
    missing_evidence: list[str]
    created_at: datetime | None = None


class InvestigationHypothesisRequest(BaseModel):
    hypothesis_id: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1, max_length=5000)
    status: str = Field(default="open")
    supporting_signal_ids: list[str] = Field(default_factory=list)
    contradicting_signal_ids: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    investigator_note: str | None = None


class InvestigationHypothesisResponse(BaseModel):
    hypothesis_id: str
    installation_id: str
    case_id: str
    title: str
    description: str
    status: str
    supporting_signal_ids: list[str]
    contradicting_signal_ids: list[str]
    confidence: float
    investigator_note: str | None = None
    created_at: datetime
    updated_at: datetime | None = None


class InvestigationSummaryResponse(BaseModel):
    finding: str
    confidence: float
    supporting_facts: list[str]
    alternative_explanations: list[str]
    missing_evidence: list[str]
    requires_human_review: bool


class InvestigationBundleResponse(BaseModel):
    investigation_id: str
    installation_id: str
    case_id: str | None = None
    anchor_event_ids: list[str]
    events: list[IntelligenceEventResponse]
    relationships: list[RelationshipResponse]
    signals: list[CorrelationSignalResponse]
    hypotheses: list[InvestigationHypothesisResponse]
    missing_evidence: list[str]
    summary: InvestigationSummaryResponse
    created_at: datetime


class CorrelateCaseRequest(BaseModel):
    window_before_minutes: int = Field(default=60, ge=0, le=1440)
    window_after_minutes: int = Field(default=60, ge=0, le=1440)


class CorrelateCaseResponse(BaseModel):
    case_id: str
    events_evaluated: int
    signals_detected: int
    signals: list[CorrelationSignalResponse]
    investigation_bundle_id: str
