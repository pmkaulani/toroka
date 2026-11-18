from __future__ import annotations

from decimal import Decimal
from typing import Any, Literal
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
    approval_record_id: str | None = None
    approved_validation_run_id: str | None = None
    approved_validation_digest: str | None = None
    approval_rationale: str | None = None
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
    evaluator: str | None = None  # Deprecated; bound to authenticated actor by service.
    limitations: list[str] = Field(default_factory=list)


class ExecuteTrustedValidationRequest(BaseModel):
    component_id: str
    component_version: str
    dataset_digest: str
    configuration_digest: str
    plan_name: str = "production-standard-evaluation"
    metric_specs: list[dict[str, Any]] = Field(default_factory=list)


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
    validation_digest: str | None = None
    execution_provenance_digest: str | None = None
    executor_id: str | None = None
    is_trusted_execution: bool = False


class RecordReadinessAttestationRequest(BaseModel):
    release_version: str
    gate_name: str
    status: Literal["PASS", "FAIL", "BLOCKED"] = "PASS"
    rationale: str
    evidence_reference: str
    evidence_digest: str


class CreateReleaseRequest(BaseModel):
    version: str
    environment: str = "validation"  # development, validation, pilot, production
    components: dict[str, str] = Field(default_factory=dict)
    validation_runs: list[str] = Field(default_factory=list)
    approval_records: list[str] = Field(default_factory=list)
    readiness_gates: list[dict[str, Any]] = Field(default_factory=list)


class PromoteReleaseRequest(BaseModel):
    target_environment: Literal["pilot", "production"]
    signature_bundle: dict[str, Any] | None = None


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
    signature_bundle: dict[str, Any] | None = None
    is_digitally_signed: bool = False
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
    signature_bundle: dict[str, Any] | None = None
    merkle_proof: dict[str, Any] | None = None
    is_digitally_signed: bool = False
    is_verified: bool
    evidence_records: list[dict[str, Any]] = Field(default_factory=list)
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
    review_status: str | None = None
    registered_by: str | None = None
    approved_by: str | None = None
    approved_at: str | None = None
    review_notes: str | None = None


class ReadinessGateInputSchema(BaseModel):
    gate_name: str
    status: str
    verified_by: str
    rationale: str
    evidence_reference: str | None = None


class EvaluateReadinessGatesRequest(BaseModel):
    release_version: str
    gates: list[ReadinessGateInputSchema]


class RecordReadinessAttestationRequest(BaseModel):
    release_version: str
    gate_name: str
    status: str = "pass"
    rationale: str
    evidence_reference: str
    evidence_digest: str


class ReadinessAttestationResponse(BaseModel):
    attestation_id: str
    installation_id: str
    release_version: str
    gate_name: str
    status: str
    verified_by: str
    verified_role: str
    rationale: str
    evidence_reference: str
    evidence_digest: str
    is_active: bool
    created_at: str


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


# ==============================================================================
# Phase 13.0 Schemas: PKI Signatures, Quantitative Risk & Shadow Governance
# ==============================================================================

class SignArtifactRequest(BaseModel):
    key_id: str = "key-toroka-bank-root"
    algorithm: str = "Ed25519"  # Ed25519 or ECDSA_P256


class VerifyArtifactRequest(BaseModel):
    trusted_public_key_pem: str | None = None


class VerifyArtifactResponse(BaseModel):
    is_valid: bool
    artifact_id: str
    artifact_type: str  # passport or release
    digest_verified: bool
    is_digitally_signed: bool
    signature_verified: bool
    signing_key_id: str | None = None
    signing_algorithm: str | None = None
    error: str | None = None
    digest_integrity_valid: bool = False
    signature_math_valid: bool = False
    signer_trusted: bool = False


class EvaluateQuantitativeDriftRequest(BaseModel):
    component_id: str
    component_version: str
    baseline_scores: list[float]
    current_scores: list[float]
    subgroup_predictions: dict[str, list[bool]] | None = None


class QuantitativeDriftEvaluationResponse(BaseModel):
    evaluation_id: str
    installation_id: str
    component_id: str
    component_version: str
    psi_score: float
    psi_severity: str
    requires_mitigation: bool
    ks_statistic: float
    ks_p_value: float
    ks_drift_detected: bool
    wasserstein_distance: float
    fairness_compliant: bool
    is_compliant: bool
    governance_findings: list[str]
    evaluation_details: dict[str, Any]
    evaluated_by: str
    created_at: str


class EvaluateChampionChallengerRequest(BaseModel):
    component_id: str
    champion_version: str
    challenger_version: str
    champion_metrics: dict[str, Any]
    challenger_metrics: dict[str, Any]
    min_sample_size: int = 100
    max_fdr_increase: float = 0.02
    min_f1_retention: float = 0.98
    max_p95_latency_ms: float = 250.0
    subgroup_predictions: dict[str, list[bool]] | None = None


class ChampionChallengerRunResponse(BaseModel):
    run_id: str
    installation_id: str
    component_id: str
    champion_version: str
    challenger_version: str
    decision: str
    is_promotable: bool
    fdr_delta: float
    f1_ratio: float
    latency_p95_delta_ms: float
    reasons: list[str]
    champion_metrics: dict[str, Any]
    challenger_metrics: dict[str, Any]
    evaluated_by: str
    created_at: str


# ==============================================================================
# Phase 13.1 Schemas: Forensic Dossiers, ISO 20022 & Semantic Grounding
# ==============================================================================

class CustodyEventSchema(BaseModel):
    event_id: str
    timestamp: str
    actor_subject: str
    actor_role: str
    action: str
    source_hash: str
    destination_hash: str
    notes: str = ""


class Section106BCertificateSchema(BaseModel):
    certificate_id: str
    statutory_framework: str
    certifier_name: str
    certifier_designation: str
    certifier_organization: str
    device_identification: str
    operating_condition_statement: str
    hash_algorithm: str
    merkle_root_hash: str
    certified_at: str
    declaration_text: str


class CreateForensicDossierRequest(BaseModel):
    case_id: str
    title: str
    incident_type: str = "Financial Fraud & Mule Syndicate"
    fraud_loss_amount: float = 0.0
    currency: str = "KES"
    case_summary: str
    attack_path_summary: dict[str, Any] = Field(default_factory=dict)
    identified_mule_nodes: list[dict[str, Any]] = Field(default_factory=list)
    evidence_records: list[dict[str, Any]] = Field(default_factory=list)
    certifier_name: str | None = None
    certifier_designation: str | None = None
    declaration_text: str | None = None


class ForensicDossierResponse(BaseModel):
    dossier_id: str
    installation_id: str
    case_id: str
    title: str
    incident_type: str
    fraud_loss_amount: float
    currency: str
    examiner_subject: str
    examiner_role: str
    case_summary: str
    attack_path_summary: dict[str, Any]
    identified_mule_nodes: list[dict[str, Any]]
    evidence_records: list[dict[str, Any]]
    chain_of_custody: list[dict[str, Any]]
    section_106b_certificate: dict[str, Any] | None = None
    dossier_digest: str
    signature_bundle: dict[str, Any] | None = None
    is_digitally_signed: bool = False
    is_verified: bool
    status: str
    created_at: str


class InflightPaymentEvaluationRequest(BaseModel):
    end_to_end_id: str
    msg_id: str | None = None
    amount: Decimal
    currency: str = "KES"
    clearing_rail: Literal["PESALINK", "KEPSS_RTGS", "MPESA_B2C", "MPESA_B2B", "MPESA_C2B", "SWIFT", "INTERNAL_BOOK"] = "PESALINK"
    debtor_name: str
    debtor_account: str
    debtor_bic: str = "KCBKKENA"
    debtor_msisdn: str | None = None
    debtor_national_id: str | None = None
    creditor_name: str
    creditor_account: str
    creditor_bic: str = "EQBLKENA"
    creditor_msisdn: str | None = None
    creditor_national_id: str | None = None
    remittance_narrative: str = ""
    account_prior_transfers_count: int | None = None
    # Phase 14.0 Extensions: Confirmation of Payee & Graduated Controls
    cop_status: Literal["MATCH", "CLOSE_MATCH", "NO_MATCH"] | None = None
    cop_match_score: float | None = None
    beneficiary_inflow_restriction: bool = False
    debtor_channel_anomaly: bool = False
    enable_graduated_controls: bool = True
    # Phase 14.1 Extensions: Telecom Scam Signal Live Telemetry
    telecom_call_status: Literal["IDLE", "CALL_IN_PROGRESS", "RECENT_CALL", "UNKNOWN"] | None = None
    telecom_coercion_score: float | None = None


class InflightPaymentEvaluationResponse(BaseModel):
    end_to_end_id: str
    decision: str
    risk_score: float
    risk_tier: str
    triggered_rules: list[str]
    recommended_action: str
    latency_ms: float
    evaluated_at: str
    integration_mode: str = "SHADOW"
    cop_status: str | None = None
    cop_match_score: float | None = None
    telecom_call_status: str | None = None
    telecom_coercion_score: float | None = None
    is_telecom_coerced: bool = False


# ==============================================================================
# Phase 14.0: Confirmation of Payee (CoP) Schemas
# ==============================================================================

class CopVerifyRequest(BaseModel):
    intended_name: str
    registered_name: str
    account_number: str
    account_type: Literal["PERSONAL", "BUSINESS"] = "PERSONAL"
    clearing_rail: str = "PESALINK"
    bank_bic: str = ""
    inquiry_id: str | None = None


class CopVerifyResponse(BaseModel):
    inquiry_id: str
    status: Literal["MATCH", "CLOSE_MATCH", "NO_MATCH"]
    match_score: float
    intended_name_normalized: str
    registered_name_normalized: str
    suggested_name: str | None = None
    reason_code: str
    advisory_message: str
    inquiry_digest: str
    verified_at: str


class SemanticVerifyRequest(BaseModel):
    claims: list[dict[str, Any]]
    evidence_context: list[dict[str, Any]] = Field(default_factory=list)
    case_id: str | None = None


class SemanticVerifyResponse(BaseModel):
    is_valid: bool
    verification_scope: str = "CALLER_SUPPLIED_EXCERPTS_ONLY_NOT_SOURCE_AUTHENTICATION"
    methodology: str = "HEURISTIC_TRIAGE"
    total_claims: int
    entailed_claims: int
    contradicted_claims: int
    numeric_mismatches: int
    ungrounded_claims: int
    evaluations: list[dict[str, Any]]


class ApproveAIProviderRequest(BaseModel):
    review_notes: str
    privacy_evidence_reference: str | None = None
    contractual_evidence_reference: str | None = None
    subprocessor_compliance: bool = True


class RegisterTrustedSignerRequest(BaseModel):
    key_id: str
    public_key_pem: str
    algorithm: Literal["Ed25519", "ECDSA_P256"] = "Ed25519"
    purpose: Literal["RELEASE_PROMOTION", "FORENSIC_DOSSIER", "EVIDENCE_PASSPORT", "AUDIT_ATTESTATION"] = "RELEASE_PROMOTION"
    security_level: Literal["BANK_MANAGED_HSM", "CLOUD_KMS", "DEV_SOFTWARE"] = "BANK_MANAGED_HSM"


class TrustedSignerResponse(BaseModel):
    key_id: str
    installation_id: str
    algorithm: str
    purpose: str
    security_level: str
    is_active: bool
    is_revoked: bool = False
    revocation_reason: str | None = None
    created_at: str


# ==============================================================================
# Phase 14.1: Telecom Scam Signal Schemas
# ==============================================================================

class TelecomSignalRequest(BaseModel):
    msisdn: str
    carrier: Literal["SAFARICOM", "AIRTEL", "TELKOM", "UNKNOWN"] = "SAFARICOM"
    query_id: str | None = None
    simulated_call_status: Literal["IDLE", "CALL_IN_PROGRESS", "RECENT_CALL", "UNKNOWN"] | None = None
    simulated_call_duration_seconds: int = 0
    simulated_sim_swap_age_hours: float | None = None


class TelecomSignalResponse(BaseModel):
    query_id: str
    msisdn: str
    carrier: str
    call_status: str
    call_duration_seconds: int
    sim_swap_status: str
    sim_swap_age_hours: float | None = None
    scam_signal_score: float
    is_high_coercion_risk: bool
    coercion_indicators: list[str]
    advisory_action: str
    statutory_warning: str | None = None
    query_digest: str
    queried_at: str


