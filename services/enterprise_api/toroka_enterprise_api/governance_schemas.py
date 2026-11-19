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
    # Phase 14.2 Extensions: Federated Mule Directory & Hash-Linked Interbank Blacklist
    check_federated_mule_directory: bool = False
    # Phase 14.4 Extensions: Swiss SIC5 Sub-50ms Parallel Clearing Engine
    use_parallel_pipeline: bool = True
    sla_budget_ms: float = 45.0
    simulated_latencies: dict[str, float] | None = None
    # Phase 15.0 - 15.3 Global Frontier Hardening Extensions
    check_money_lock: bool = True
    enforce_nighttime_limits: bool = False
    client_local_hour: int | None = None
    # Phase 15.2 Hardware & SIM Binding
    sim_device_imei_hash: str | None = None
    sim_iccid_hash: str | None = None
    sim_is_emulator: bool = False
    sim_is_rooted: bool = False
    sim_swap_hours_ago: float | None = None
    # Phase 15.3 BioCatch Behavioral Biometrics
    biometrics_trajectory_r2: float | None = None
    biometrics_micro_tremor_hz: float | None = None
    biometrics_is_active_call: bool | None = None
    biometrics_is_remote_software: bool | None = None
    biometrics_hesitation_ms: int | None = None
    biometrics_backspaces: int | None = None
    # Phase 16.0 Global Frontier Defenses Complete Extensions
    check_kill_switch: bool = True
    enforce_safe_accounts: bool = False
    check_ip_ingress: bool = False
    client_ip: str | None = None
    client_country_code: str | None = None
    is_vpn: bool = False
    is_tor: bool = False
    is_datacenter_proxy: bool = False
    registered_overseas_travel: bool = False
    enforce_accord_delay: bool = False
    is_first_time_payee: bool = False
    check_scameter: bool = False
    scameter_proxy_id: str | None = None
    scameter_waiver_id: str | None = None


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
    is_federated_mule: bool = False
    federated_mule_tier: str | None = None
    # Phase 14.4 Swiss SIC5 Telemetry
    is_parallel_pipeline: bool = False
    sla_budget_ms: float = 45.0
    is_sla_compliant: bool = True
    cop_latency_ms: float | None = None
    telecom_latency_ms: float | None = None
    federated_mule_latency_ms: float | None = None
    behavioral_latency_ms: float | None = None
    feed_statuses: dict[str, str] | None = None
    circuit_breaker_tripped: bool = False
    # Phase 15 Global Frontier Hardening Outputs
    money_lock_active: bool = False
    money_lock_available_balance: float | None = None
    money_lock_locked_balance: float | None = None
    is_money_lock_breach: bool = False
    is_nighttime_breach: bool = False
    nighttime_ceiling: float | None = None
    precautionary_hold_id: str | None = None
    precautionary_hold_state: str | None = None
    sim_binding_status: str | None = None
    is_emulator_detected: bool = False
    biometrics_verdict: str | None = None
    biometrics_risk_score: float | None = None
    is_rat_detected: bool = False
    # Phase 16 Global Frontier Complete Outputs
    is_kill_switch_active: bool = False
    is_designated_safe_payee: bool | None = None
    safe_accounts_breach: bool = False
    ip_ingress_verdict: str | None = None
    accord_delay_hours: int = 0
    accord_warning_message: str | None = None
    scameter_risk_level: str | None = None
    is_scameter_shielded: bool = False


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


# ==============================================================================
# Phase 14.2: Federated Mule Directory Schemas (PBOC Art. 21 / US EWS / Swiss SMPC)
# ==============================================================================

class RegisterFederatedMuleRequest(BaseModel):
    entity_type: Literal["BANK_ACCOUNT", "MSISDN", "NATIONAL_ID", "PAYBILL_TILL"] = "BANK_ACCOUNT"
    value: str
    severity_tier: Literal["SUSPECT_MULE", "CORROBORATED_MULE", "CONFIRMED_SYNDICATE_CONTROLLER"] = "CORROBORATED_MULE"
    originating_bank_bic: str = ""
    reason_code: str = "SUSPICIOUS_MULE_ACTIVITY"
    dossier_reference: str | None = None
    ttl_days: int | None = 365


class FederatedMuleEntryResponse(BaseModel):
    entry_id: str
    installation_id: str
    entity_type: str
    blinded_token: str
    cleartext_preview: str
    severity_tier: str
    originating_bank_bic: str
    reason_code: str
    dossier_reference: str | None = None
    status: str
    registered_by: str | None = None
    registered_at: str
    expires_at: str | None = None


class QueryFederatedMuleRequest(BaseModel):
    entity_type: Literal["BANK_ACCOUNT", "MSISDN", "NATIONAL_ID", "PAYBILL_TILL"] = "BANK_ACCOUNT"
    value: str
    is_already_blinded: bool = False


class QueryFederatedMuleResponse(BaseModel):
    is_match: bool
    blinded_token: str
    cleartext_preview: str
    entity_type: str
    severity_tier: str | None = None
    originating_bank_bic: str | None = None
    reason_code: str | None = None
    dossier_reference: str | None = None
    status: str
    registered_at: str | None = None
    expires_at: str | None = None
    recommended_action: str


class UpdateFederatedMuleStatusRequest(BaseModel):
    status: Literal["ACTIVE", "CONTESTED", "EXPUNGED"]
    justification: str


# ==============================================================================
# Phase 14.3: Multi-Tiered Mule Tracing & Graph Cascade Schemas (PBOC / UK PSR)
# ==============================================================================

class TriggerMuleCascadeTraceRequest(BaseModel):
    root_account: str
    root_fraud_amount: Decimal
    currency: str = "KES"
    root_transaction_id: str | None = None
    anchor_time: str | None = None
    max_hops: int = 3
    time_window_hours: int = 72
    local_bank_bic: str = "KCBKKENA"
    transfers: list[dict[str, Any]] | None = None
    account_metadata: dict[str, dict[str, Any]] | None = None


class MuleCascadeTraceResponse(BaseModel):
    trace_id: str
    installation_id: str
    root_account: str
    root_transaction_id: str | None = None
    root_fraud_amount: str
    currency: str
    max_depth_reached: int
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    total_nodes_identified: int
    total_frozen_or_held_amount: str
    recovery_potential_ratio: float
    created_at: str
    status: str
    directives: list[dict[str, Any]]


class ExecuteCascadeDirectiveRequest(BaseModel):
    directive_id: str
    action: Literal["EXECUTE_LOCAL_HOLD", "DISPATCH_CAMT056", "REJECT"]
    justification: str | None = None


class ExecuteCascadeDirectiveResponse(BaseModel):
    directive_id: str
    trace_id: str
    status: str
    action_taken: str
    camt056_xml: str | None = None
    executed_at: str


# ==============================================================================
# Phase 15.0: Singapore MAS Money Lock Schemas
# ==============================================================================

class MoneyLockLockRequest(BaseModel):
    amount: Decimal
    actor: str = "CUSTOMER_PORTAL"


class MoneyLockBranchUnlockRequest(BaseModel):
    amount: Decimal
    officer_id: str
    station_id: str
    dual_authorizer_id: str | None = None
    channel: Literal["PHYSICAL_BRANCH_COUNTER", "PHYSICAL_ATM_CHIP_PIN"] = "PHYSICAL_BRANCH_COUNTER"


class MoneyLockAccountResponse(BaseModel):
    account_id: str
    installation_id: str
    currency: str
    total_balance: float
    locked_vault_balance: float
    available_balance: float
    status: str
    last_locked_at: str | None = None
    last_unlocked_at: str | None = None
    unlock_channel: str | None = None
    unlock_officer_id: str | None = None
    unlock_station_id: str | None = None
    dual_authorizer_id: str | None = None
    audit_trail: list[dict[str, Any]] = []


# ==============================================================================
# Phase 15.1: Brazil BCB Bloqueio Cautelar & Recall Schemas
# ==============================================================================

class PrecautionaryHoldCreateRequest(BaseModel):
    tx_id: str
    amount: Decimal
    debtor_account: str
    creditor_account: str
    reason: str
    currency: str = "KES"
    duration_hours: int = 72


class PrecautionaryHoldReleaseRequest(BaseModel):
    officer_id: str
    resolution_notes: str


class PrecautionaryHoldEscalateRequest(BaseModel):
    officer_id: str
    resolution_notes: str


class PrecautionaryHoldRecallRequest(BaseModel):
    recall_requested_at: str | None = None


class PrecautionaryHoldResponse(BaseModel):
    hold_id: str
    installation_id: str
    tx_id: str
    amount: float
    currency: str
    debtor_account: str
    creditor_account: str
    state: str
    placed_at: str
    expires_at: str
    reason: str
    statutory_basis: str
    decision_officer_id: str | None = None
    resolution_notes: str | None = None
    camt056_xml: str | None = None


# ==============================================================================
# Phase 15.2: India NPCI SIM & Hardware Binding Schemas
# ==============================================================================

class SimBindingEnrollRequest(BaseModel):
    account_id: str
    device_imei: str
    sim_iccid: str
    carrier_name: str = "Safaricom"


class SimBindingEnrollResponse(BaseModel):
    account_id: str
    installation_id: str
    bound_device_imei_hash: str
    bound_sim_iccid_hash: str
    carrier_name: str
    status: str
    enrolled_at: str


# ==============================================================================
# Phase 16.0: Singapore SRF & 24/7 Customer Kill Switch Schemas
# ==============================================================================

class SrfAdjudicationRequest(BaseModel):
    account_id: str
    disputed_amount: Decimal
    enforced_token_cooling_12h: bool = True
    real_time_alert_dispatched: bool = True
    kill_switch_available_24_7: bool = True
    fraud_surveillance_active: bool = True
    checked_ssir_registry: bool = True
    blocked_sender_id_spoofing: bool = True
    filtered_malicious_urls: bool = True
    consumer_gross_negligence: bool = False


class SrfAdjudicationResponse(BaseModel):
    claim_id: str
    account_id: str
    disputed_amount: str
    liability_verdict: str
    primary_liable_party: str
    reimbursement_bank_amount: str
    reimbursement_telco_amount: str
    consumer_liability_amount: str
    identified_breaches: list[str]
    adjudication_timestamp: str
    statutory_reference: str


class CustomerKillSwitchActivateRequest(BaseModel):
    channel: Literal["MOBILE_PANIC_BUTTON", "WEB_EMERGENCY_PORTAL", "IVR_HOTLINE_AUTO", "BRANCH_OFFICER_OVERRIDE"] = "MOBILE_PANIC_BUTTON"
    reason: str = "Suspected unauthorized account access / remote takeover"
    active_sessions_to_revoke: int = 1


class CustomerKillSwitchDeactivateRequest(BaseModel):
    maker_officer: str
    checker_officer: str
    branch_code: str
    notes: str = "Physical customer in-branch identity verification passed"


class CustomerKillSwitchResponse(BaseModel):
    account_id: str
    customer_id: str
    installation_id: str
    status: str
    activated_at: str | None = None
    channel_initiated: str | None = None
    activation_reason: str | None = None
    revoked_sessions_count: int = 0
    deactivated_at: str | None = None
    deactivation_maker_officer: str | None = None
    deactivation_checker_officer: str | None = None
    deactivation_branch_code: str | None = None


# ==============================================================================
# Phase 16.1: South Korea FSS Designated Safe Accounts & Delayed ATM Schemas
# ==============================================================================

class SafeAccountRegisterRequest(BaseModel):
    payee_account: str
    payee_institution: str = "Safaricom"
    label: str


class SafeAccountResponse(BaseModel):
    registration_id: str
    account_id: str
    installation_id: str
    payee_account: str
    payee_institution: str
    label: str
    is_active: bool
    registered_at: str


class AtmDepositInboundRequest(BaseModel):
    amount: Decimal
    reference: str


class AtmWithdrawalEvaluateRequest(BaseModel):
    amount: Decimal


class AtmWithdrawalEvaluateResponse(BaseModel):
    account_id: str
    allowed: bool
    reason: str
    hold_id: str | None = None
    inbound_amount: str | None = None
    hold_expiry_timestamp: str | None = None


# ==============================================================================
# Phase 16.2: Brazil BCB Limit Increase Cooling-off & Pix MED 2.0 Schemas
# ==============================================================================

class LimitIncreaseRequestCreate(BaseModel):
    limit_type: Literal["DAILY_P2P", "NIGHTTIME", "SINGLE_TX"] = "DAILY_P2P"
    requested_limit: Decimal


class LimitIncreaseResponse(BaseModel):
    request_id: str
    account_id: str
    limit_type: str
    current_limit: str
    requested_limit: str
    requested_at: str
    effective_at: str
    is_cooling: bool
    status_message: str


class Med2HopEdgeInput(BaseModel):
    edge_id: str
    source_account: str
    target_account: str
    target_institution_bic: str
    amount: Decimal
    hop_tier: int  # 1 to 5
    timestamp: str | None = None


class Med2CascadeTraceRequest(BaseModel):
    original_tx_id: str
    victim_account: str
    total_stolen_amount: Decimal
    incident_timestamp: str
    edges: list[Med2HopEdgeInput]
    account_balances: dict[str, Decimal]


class Med2CascadeTraceResponse(BaseModel):
    contestation_id: str
    original_tx_id: str
    victim_account: str
    total_stolen_amount: str
    reported_at: str
    is_within_80_day_window: bool
    total_clawback_holds_placed: str
    recovery_rate_pct: float
    hops: list[dict[str, Any]]
    statutory_basis: str


# ==============================================================================
# Phase 16.3: India I4C Helpline 1930 Golden Hour Schemas
# ==============================================================================

class TargetRecipientInput(BaseModel):
    recipient_account: str
    recipient_institution_bic: str
    amount_flagged: Decimal
    freeze_action: str = "LOCK_ALL_OUTBOUND_AND_ATM"


class GoldenHourReportCreateRequest(BaseModel):
    victim_account_id: str
    victim_phone: str
    scam_category: str
    incident_timestamp: str
    total_amount_lost: Decimal
    transaction_references: list[str]
    target_recipients: list[TargetRecipientInput]


class GoldenHourReportResponse(BaseModel):
    report_id: str
    victim_account_id: str
    victim_phone: str
    scam_category: str
    incident_timestamp: str
    reported_timestamp: str
    elapsed_minutes: float
    is_golden_hour: bool
    status: str
    total_amount_lost: str
    transaction_references: list[str]
    target_recipients_count: int
    switch_freeze_broadcast_id: str | None = None
    switch_status: str
    statutory_authority: str


# ==============================================================================
# Phase 16.4: Hong Kong FPS Scameter Schemas
# ==============================================================================

class ScameterLookupRequest(BaseModel):
    proxy_id: str
    proxy_type: Literal["PHONE", "EMAIL", "ACCOUNT", "NATIONAL_ID"] = "PHONE"


class ScameterLookupResponse(BaseModel):
    proxy_id: str
    proxy_type: str
    risk_level: str
    police_report_reference: str | None = None
    unskippable_warning_required: bool
    warning_title: str
    warning_body: str
    requires_liability_waiver: bool


class ScameterWaiverCreateRequest(BaseModel):
    account_id: str
    customer_id: str
    proxy_id: str
    risk_level: str
    transfer_amount: Decimal
    customer_consent_ack: bool = True


class ScameterWaiverResponse(BaseModel):
    waiver_id: str
    account_id: str
    customer_id: str
    proxy_id: str
    risk_level: str
    transfer_amount: str
    signed_timestamp: str
    waiver_hash: str
    is_institution_shielded: bool
    statutory_framework: str

