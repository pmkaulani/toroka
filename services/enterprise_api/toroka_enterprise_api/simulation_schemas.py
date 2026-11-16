"""Pydantic schemas for the counterfactual investigation simulator API."""
from __future__ import annotations

from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class SimulationStrategyCreate(BaseModel):
    strategy_id: str = Field(..., min_length=2, max_length=100)
    title: str = Field(..., min_length=2, max_length=255)
    description: str = Field(default="", max_length=2000)
    rules_enabled: list[str] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)
    min_severity: str = Field(default="medium")
    min_confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class SimulationStrategyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    strategy_id: str
    version: int
    installation_id: str
    title: str
    description: str
    rules_enabled: list[str]
    parameters: dict[str, Any]
    min_severity: str
    min_confidence: float
    status: str
    created_by: str
    created_at: str


class CaseOutcomeCreate(BaseModel):
    case_id: str = Field(..., min_length=1, max_length=64)
    label: str = Field(..., description="confirmed_fraud, confirmed_legitimate, inconclusive, unlabelled")
    first_fraud_event_time: datetime | None = None
    notes: str | None = None


class CaseOutcomeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    case_id: str
    installation_id: str
    label: str
    first_fraud_event_time: str | None
    adjudicated_at: str
    adjudicated_by: str
    notes: str | None


class SimulationRunRequest(BaseModel):
    strategy_id: str
    strategy_version: int | None = None
    baseline_strategy_id: str | None = None
    baseline_strategy_version: int | None = None
    simulation_cutoff: datetime | None = None
    cohort_case_ids: list[str] | None = None


class SimulationRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    simulation_id: str
    installation_id: str
    strategy_id: str
    strategy_version: int
    baseline_strategy_id: str | None
    baseline_strategy_version: int | None
    executed_by: str
    executed_at: str
    simulation_cutoff: str | None
    metrics: dict[str, Any]
    baseline_metrics: dict[str, Any] | None
    delta: dict[str, Any] | None
    total_events_replayed: int
    delayed_events_filtered: int
    case_detections: dict[str, list[dict[str, Any]]]


class SimulationApprovalRequestCreate(BaseModel):
    strategy_id: str
    strategy_version: int | None = None
    request_rationale: str = Field(..., min_length=5, max_length=2000)
    simulation_run_id: str | None = None


class SimulationApprovalReviewCreate(BaseModel):
    decision: str = Field(..., description="approved or rejected")
    notes: str | None = Field(default=None, max_length=2000)


class SimulationApprovalResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    approval_id: str
    installation_id: str
    strategy_id: str
    strategy_version: int
    requester_subject: str
    requested_at: str
    request_rationale: str
    simulation_run_id: str | None
    status: str
    reviewer_subject: str | None
    reviewed_at: str | None
    review_decision: str | None
    review_notes: str | None
