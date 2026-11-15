"""Pydantic schemas for behavioral baselines, deviations, anomalies, and prioritization."""
from __future__ import annotations

from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class BaselineStatisticsResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    count: int
    mean: float
    standard_deviation: float
    minimum: float
    maximum: float
    median: float | None = None


class BehavioralProfileResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    installation_id: str
    subject_id: str
    subject_type: str
    sample_count: int
    maturity: str
    observation_start: datetime
    observation_end: datetime
    dimensions: dict[str, Any]
    created_at: datetime
    updated_at: datetime | None = None


class BehavioralAnomalyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    anomaly_id: str
    installation_id: str
    case_id: str | None = None
    subject_id: str
    dimension: str
    observed_value: float
    expected_value: float
    deviation: float
    severity: str
    confidence: float
    baseline_sample_count: int
    baseline_mature: bool
    explanation: str
    limitations: list[str] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class EvaluateObservationRequest(BaseModel):
    dimension: str
    observed_value: float
    case_id: str | None = None
    historical_samples: list[float] = Field(default_factory=list)
    observation_context: dict[str, Any] = Field(default_factory=dict)


class InvestigationPriorityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    priority_score: float
    reasons: list[str]
    requires_review: bool
    independent_sources_count: int = 1
    unresolved_contradictions: int = 0
    triage_notice: str = (
        "Operational triage priority only; not an assessment or probability of guilt or fraud."
    )


class DetectionMethodResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    method_id: str
    version: str
    status: str
    description: str
    training_data: str | None = None
    validation_reference: str | None = None
    approved_by: str | None = None
    limitations: list[str] = Field(default_factory=list)
    created_at: datetime


class BaselineAdmissionRequest(BaseModel):
    event_id: str
    subject_id: str
    event_is_verified: bool
    event_is_under_investigation: bool
    event_is_correction: bool
    event_is_test_data: bool
    event_is_compromised: bool = False


class BaselineAdmissionResponse(BaseModel):
    event_id: str
    subject_id: str
    accepted: bool
    reason: str
