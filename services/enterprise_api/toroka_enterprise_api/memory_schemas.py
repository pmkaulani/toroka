"""Pydantic schemas for Phase 9: Fraud DNA & Institutional Memory Engine."""
from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class FingerprintResponse(BaseModel):
    case_id: str
    installation_id: str
    extractor_version: str
    features: dict[str, str]
    source_systems: list[str]
    source_coverage: float
    total_events: int
    first_event_time: str | None = None
    last_event_time: str | None = None
    control_weaknesses: list[str]
    adjudicated_label: str | None = None
    created_at: str


class InstitutionalPatternCreate(BaseModel):
    pattern_id: str = Field(..., min_length=3, max_length=100)
    title: str = Field(..., min_length=3, max_length=255)
    description: str = Field(..., min_length=5)
    feature_signature: dict[str, str] = Field(default_factory=dict)
    confirmed_fraud_case_ids: list[str] = Field(default_factory=list)
    confirmed_legitimate_case_ids: list[str] = Field(default_factory=list)
    independent_source_systems: list[str] = Field(default_factory=list)
    control_weaknesses: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class InstitutionalPatternResponse(BaseModel):
    pattern_id: str
    installation_id: str
    version: int
    title: str
    description: str
    feature_signature: dict[str, str]
    confirmed_fraud_case_ids: list[str]
    confirmed_legitimate_case_ids: list[str]
    independent_source_systems: list[str]
    status: str
    extractor_version: str
    control_weaknesses: list[str]
    curator_subject: str
    reviewer_subject: str | None = None
    reviewed_at: str | None = None
    validation_rationale: str | None = None
    limitations: list[str]
    created_at: str
    updated_at: str | None = None


class PatternEvaluationResponse(BaseModel):
    pattern_id: str
    version: int
    eligible_for_review: bool
    checks: dict[str, bool]
    blockers: list[str]
    details: dict[str, Any]


class PatternReviewRequest(BaseModel):
    action: str = Field(..., pattern="^(submit_for_review|validate|reject|suspend|reinstate|retire)$")
    rationale: str = Field(..., min_length=5)


class PatternReviewResponse(BaseModel):
    review_id: str
    pattern_id: str
    pattern_version: int
    reviewer_subject: str
    action: str
    rationale: str
    created_at: str


class PatternVersionResponse(BaseModel):
    pattern_id: str
    version: int
    title: str
    description: str
    feature_signature: dict[str, str]
    status: str
    changed_by: str
    change_summary: str
    created_at: str


class CaseSimilarityResponse(BaseModel):
    current_case_id: str
    historical_case_id: str
    similarity_index: float | None
    comparison_coverage: float
    matched_features: list[str]
    different_features: list[str]
    historical_outcome: str | None
    historical_control_weaknesses: list[str]
    shared_control_weaknesses: list[str]
    summary_explanation: str


class PatternMatchResponse(BaseModel):
    pattern_id: str
    pattern_version: int
    pattern_title: str
    pattern_status: str
    similarity_index: float | None
    comparison_coverage: float
    matched_features: list[str]
    different_features: list[str]
    control_weaknesses: list[str]
    explanation: str
    confirmed_fraud_cases_count: int
    confirmed_legitimate_cases_count: int


class MemoryOverviewResponse(BaseModel):
    adjudicated_case_count: int
    validated_pattern_count: int
    candidate_pattern_count: int
    under_review_pattern_count: int
    suspended_pattern_count: int
    retired_pattern_count: int
    average_source_coverage: float
    total_fingerprinted_cases: int
    recent_reviews: list[PatternReviewResponse]
