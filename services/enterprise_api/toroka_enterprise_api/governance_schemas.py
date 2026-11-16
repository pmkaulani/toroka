from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class CreateComponentRequest(BaseModel):
    component_id: str
    version: str
    component_type: str  # rule, detector, statistical_model, ml_model, llm, prompt, policy, simulation
    name: str
    risk_tier: str  # low, moderate, high, critical
    owner_team: str
    source_digest: str
    configuration_digest: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    description: str = ""


class GovernedComponentResponse(BaseModel):
    component_id: str
    version: str
    installation_id: str
    component_type: str
    name: str
    status: str
    risk_tier: str
    owner_team: str
    source_digest: str
    configuration_digest: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    created_by: str
    approved_by: str | None = None
    approved_at: str | None = None
    suspended_by: str | None = None
    suspended_at: str | None = None
    retired_by: str | None = None
    retired_at: str | None = None
    created_at: str
    updated_at: str


class ApproveComponentRequest(BaseModel):
    validation_run_id: str
    validation_digest: str
    rationale: str


class ValidationMetricSchema(BaseModel):
    name: str
    value: float
    threshold: float | None = None
    direction: str | None = "gte"
    result: str  # pass, fail, inconclusive


class CreateValidationRunRequest(BaseModel):
    component_id: str
    component_version: str
    dataset_digest: str
    configuration_digest: str
    metrics: list[ValidationMetricSchema]
    evaluator: str
    limitations: list[str] = Field(default_factory=list)


class ValidationRunResponse(BaseModel):
    run_id: str
    installation_id: str
    component_id: str
    component_version: str
    dataset_digest: str
    configuration_digest: str
    metrics: list[ValidationMetricSchema]
    result: str
    evaluator: str
    limitations: list[str] = Field(default_factory=list)
    started_at: str
    completed_at: str
    created_at: str


class CreateReleaseRequest(BaseModel):
    version: str
    environment: str = "validation"  # development, validation, pilot, production
    components: dict[str, str] = Field(default_factory=dict)
    validation_runs: list[str] = Field(default_factory=list)
    approval_records: list[str] = Field(default_factory=list)
    readiness_gates: list[dict[str, Any]] = Field(default_factory=list)


class PromoteReleaseRequest(BaseModel):
    target_environment: str  # pilot, production


class RollbackReleaseRequest(BaseModel):
    target_release_id: str
    reason: str


class ProductionReleaseResponse(BaseModel):
    release_id: str
    installation_id: str
    version: str
    environment: str
    status: str
    components_manifest: dict[str, Any]
    validation_runs: list[str]
    approval_records: list[str]
    readiness_gates: list[dict[str, Any]]
    manifest_digest: str
    promoted_by: str | None = None
    promoted_at: str | None = None
    rollback_target_id: str | None = None
    created_by: str
    created_at: str


class SuspendComponentRequest(BaseModel):
    component_id: str
    version: str
    reason: str
    incident_id: str | None = None


class ResumeComponentRequest(BaseModel):
    component_id: str
    version: str
    reason: str


class SuspensionRecordResponse(BaseModel):
    suspension_id: str
    installation_id: str
    component_id: str
    component_version: str
    suspended_by: str
    reason: str
    incident_id: str | None = None
    is_active: bool
    suspended_at: str
    resumed_by: str | None = None
    resumed_at: str | None = None
    resume_reason: str | None = None


class CreateIncidentRequest(BaseModel):
    title: str
    category: str
    severity: str
    affected_components: list[str]
    detection_source: str = "monitoring"
    owner: str = "security_operations"
    affected_case_ids: list[str] = Field(default_factory=list)


class UpdateIncidentStatusRequest(BaseModel):
    status: str  # triaged, contained, investigating, remediated, recovered, closed
    remediation_notes: str | None = None
    post_incident_review: str | None = None


class GovernanceIncidentResponse(BaseModel):
    incident_id: str
    installation_id: str
    title: str
    category: str
    severity: str
    status: str
    affected_components: list[str]
    affected_case_ids: list[str]
    detection_source: str
    detected_at: str
    contained_at: str | None = None
    resolved_at: str | None = None
    owner: str
    remediation_notes: str | None = None
    post_incident_review: str | None = None
    created_at: str


class RecordDriftRequest(BaseModel):
    drift_type: str
    component_id: str
    metric_name: str
    baseline_value: float
    observed_value: float
    threshold: float
    recommended_response: str = ""
    details: dict[str, Any] = Field(default_factory=dict)


class DriftRecordResponse(BaseModel):
    drift_id: str
    installation_id: str
    drift_type: str
    component_id: str
    metric_name: str
    baseline_value: float
    observed_value: float
    threshold: float
    severity: str
    recommended_response: str
    details: dict[str, Any]
    detected_at: str


class SystemHealthOverviewResponse(BaseModel):
    overall_status: str
    detection_health: str
    data_quality_health: str
    network_health: str
    copilot_health: str
    audit_integrity_health: str
    active_drift_count: int
    open_incidents_count: int
    summary_message: str


class GenerateEvidencePassportRequest(BaseModel):
    finding_id: str
    case_id: str


class EvidencePassportResponse(BaseModel):
    passport_id: str
    installation_id: str
    finding_id: str
    case_id: str
    finding_type: str
    finding_status: str
    component_versions: dict[str, Any]
    configuration_digest: str
    evidence_count: int
    source_systems: list[str]
    detection_time: str
    earliest_event_time: str | None = None
    evidence_at_detection_count: int
    delayed_evidence_count: int
    contradictions_count: int
    evidence_debt_level: str
    alternative_explanations: list[str]
    validation_result: str
    human_review_required: bool
    passport_digest: str
    is_verified: bool
    created_at: str


class RegisterAIProviderRequest(BaseModel):
    provider_name: str
    model_identifier: str
    model_version: str
    hosting_location: str
    data_retention_policy: str
    training_on_customer_data_permitted: bool = False
    risk_tier: str = "high"


class GovernedAIProviderResponse(BaseModel):
    provider_id: str
    installation_id: str
    provider_name: str
    model_identifier: str
    model_version: str
    hosting_location: str
    data_retention_policy: str
    training_on_customer_data_permitted: bool
    is_approved: bool
    risk_tier: str
    evaluation_summary: dict[str, Any]
    last_evaluated_at: str | None = None
    created_at: str


class ReadinessGateInputSchema(BaseModel):
    gate_name: str
    status: str
    verified_by: str
    rationale: str
    evidence_reference: str | None = None


class EvaluateReadinessGatesRequest(BaseModel):
    release_version: str
    gates: list[ReadinessGateInputSchema]


class ReadinessAssessmentResponse(BaseModel):
    installation_id: str
    release_version: str
    overall_status: str
    is_production_ready: bool
    gates: list[dict[str, Any]]
    evaluated_at: str


class ValidationPackageResponse(BaseModel):
    installation_id: str
    generated_at: str
    release_version: str
    components_count: int
    active_detectors: list[str]
    validation_runs_count: int
    readiness_status: str
    open_incidents_count: int
    active_suspensions_count: int
    executive_summary: str
    document_sections: dict[str, Any]
