export type Role =
  | "investigator"
  | "authoriser"
  | "auditor"
  | "data_steward"
  | "system_administrator";

export interface Persona {
  id: string;
  name: string;
  role: Role;
  title: string;
  badge: string;
}

export interface CaseSummary {
  id: string;
  installation_id: string;
  label: string;
  focus: string;
  status: "open" | "closed";
  version: number;
  created_at: string;
  updated_at: string;
}

export interface CaseDetail extends CaseSummary {
  snapshot: {
    label?: string;
    focus?: string;
    staff_ref?: string;
    customer_ref?: string;
    verdict?: string;
    risk_index?: number;
    pieces?: Array<{
      provider: string;
      risk_points: number;
      label: string;
      summary: string;
      details?: Record<string, unknown>;
    }>;
    contradictions?: string[];
    unassessed?: string[];
    reasoning?: string[];
    [key: string]: unknown;
  };
  snapshot_sha256: string;
  manifest_id?: string;
  disposition?: string;
  closing_note?: string;
  alternatives_considered?: string;
  closed_at?: string;
}

export interface CaseNote {
  id: string;
  case_id: string;
  author_subject: string;
  body: string;
  created_at: string;
}

export interface CaseAssignment {
  id: string;
  case_id: string;
  assigned_subject: string;
  assignment_role: string;
  assigned_by: string;
  status: string;
  assigned_at: string;
}

export interface RevealRequest {
  id: string;
  case_id: string;
  pseudonym: string;
  requested_by: string;
  reason: string;
  status: "pending" | "approved" | "rejected" | "expired" | "used";
  created_at: string;
  expires_at: string;
  approved_by?: string;
  approved_at?: string;
  used_at?: string;
  rejection_reason?: string;
}

export interface ClosureProposal {
  id: string;
  case_id: string;
  requested_by: string;
  disposition: string;
  closing_note: string;
  alternatives_considered?: string;
  expected_case_version: number;
  status: "pending" | "approved" | "rejected" | "withdrawn";
  reviewed_by?: string;
  review_note?: string;
  requested_at: string;
  reviewed_at?: string;
}

export interface WorkbenchOverview {
  role: string;
  installation_id: string;
  open_cases_count: number;
  closed_cases_count: number;
  assigned_cases_count: number;
  pending_reveals_count: number;
  pending_closures_count: number;
  recent_runs_count: number;
  audit_records_count: number;
  contract_version: string;
}

export interface AuditTimelineItem {
  sequence: number;
  event_id: string;
  action: string;
  actor_subject: string;
  actor_role: string;
  target_type: string;
  target_id?: string;
  safe_metadata: Record<string, unknown>;
  created_at: string;
}

export interface AuditVerification {
  installation_id: string;
  valid: boolean;
  head_hash: string;
  records_verified: number;
  error?: string;
}

export interface DataContractFeed {
  runtime_key: string;
  required_feed: boolean;
  fields: Array<{
    name: string;
    required_for_ingestion: boolean;
    optional: boolean;
  }>;
}

export interface DataContractResponse {
  contract_version: string;
  feeds: Record<string, DataContractFeed>;
}

export interface DetectorReadiness {
  detector_id: string;
  status: "READY" | "DEGRADED" | "BLOCKED";
  required_feeds: string[];
  missing_required_feeds?: string[];
  supporting_feeds: string[];
  missing_supporting_feeds?: string[];
}

export interface Connector {
  connector_id: string;
  connector_type: string;
  source_system: string;
  version: string;
  enabled: boolean;
  registered_at: string;
  metadata: Record<string, unknown>;
  capabilities: Record<string, unknown>;
  cursor?: string | null;
  records_ingested: number;
}

export interface ConnectorHealth {
  connector_id: string;
  healthy: boolean;
  details?: Record<string, unknown>;
}

export interface IntegrationJob {
  job_id: string;
  installation_id: string;
  connector_id: string;
  job_type: string;
  triggered_by: string;
  status: "completed" | "running" | "failed";
  started_at: string;
  completed_at?: string | null;
  records_received: number;
  records_accepted: number;
  records_rejected: number;
  records_duplicates: number;
  records_corrected: number;
  error_message?: string | null;
  cursor_before?: string | null;
  cursor_after?: string | null;
}

export interface ReconciliationReport {
  installation_id: string;
  connector_id: string;
  window_start?: string | null;
  window_end?: string | null;
  expected_source_count?: number | null;
  ingested_record_count: number;
  corrected_record_count: number;
  rejected_record_count: number;
  discrepancy: number;
  status: "reconciled" | "discrepancy_detected";
  explanation: string;
}

export interface QualityAssessment {
  total_records: number;
  valid_records: number;
  rejected_records: number;
  issues_count: number;
  issues: Array<{
    field: string;
    issue_type: string;
    message: string;
    record_id?: string;
  }>;
  detector_impact: Array<{
    detector_id: string;
    status: "READY" | "DEGRADED" | "BLIND";
    required_missing: string[];
    optional_missing: string[];
    explanation: string;
  }>;
}

export interface IntelligenceEvent {
  event_id: string;
  installation_id: string;
  event_type: string;
  event_time: string;
  actor?: string | null;
  subject?: string | null;
  source_system?: string | null;
  source_record_id?: string | null;
  entities: string[];
  attributes: Record<string, unknown>;
  provenance_digest?: string | null;
}

export interface Relationship {
  id?: string | null;
  installation_id: string;
  source_type: string;
  source_id: string;
  target_type: string;
  target_id: string;
  relationship_type: string;
  first_seen?: string | null;
  last_seen?: string | null;
  confidence: number;
  source_system?: string | null;
  source_record_id?: string | null;
  attributes: Record<string, unknown>;
}

export interface CorrelationSignal {
  signal_id: string;
  signal_type: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  title: string;
  explanation: string;
  event_ids: string[];
  confidence: number;
  evidence: Array<Record<string, unknown>>;
  alternative_explanations: string[];
  missing_evidence: string[];
  created_at?: string | null;
}

export interface InvestigationHypothesis {
  hypothesis_id: string;
  installation_id: string;
  case_id: string;
  title: string;
  description: string;
  status: "open" | "supported" | "weakened" | "disproven";
  supporting_signal_ids: string[];
  contradicting_signal_ids: string[];
  confidence: number;
  investigator_note?: string | null;
  created_at?: string;
  updated_at?: string | null;
}

export interface InvestigationSummary {
  finding: string;
  confidence: number;
  supporting_facts: string[];
  alternative_explanations: string[];
  missing_evidence: string[];
  requires_human_review: boolean;
}

export interface InvestigationBundle {
  investigation_id: string;
  installation_id: string;
  case_id?: string | null;
  anchor_event_ids: string[];
  events: IntelligenceEvent[];
  relationships: Relationship[];
  signals: CorrelationSignal[];
  hypotheses: InvestigationHypothesis[];
  missing_evidence: string[];
  summary: InvestigationSummary;
  created_at: string;
}

export interface CorrelateCaseResponse {
  case_id: string;
  events_evaluated: number;
  signals_detected: number;
  signals: CorrelationSignal[];
  investigation_bundle_id: string;
}

export interface BaselineStatistics {
  count: number;
  mean: number;
  standard_deviation: number;
  minimum: number;
  maximum: number;
  median?: number | null;
}

export interface BehavioralProfile {
  id: string;
  installation_id: string;
  subject_id: string;
  subject_type: string;
  sample_count: number;
  maturity: "insufficient" | "developing" | "mature";
  observation_start: string;
  observation_end: string;
  dimensions: Record<string, BaselineStatistics>;
  created_at: string;
  updated_at?: string | null;
}

export interface BehavioralAnomaly {
  anomaly_id: string;
  installation_id: string;
  case_id?: string | null;
  subject_id: string;
  dimension: string;
  observed_value: number;
  expected_value: number;
  deviation: number;
  severity: "low" | "medium" | "high";
  confidence: number;
  baseline_sample_count: number;
  baseline_mature: boolean;
  explanation: string;
  limitations: string[];
  provenance: Record<string, unknown>;
  created_at: string;
}

export interface InvestigationPriority {
  priority_score: number;
  reasons: string[];
  requires_review: boolean;
  independent_sources_count: number;
  unresolved_contradictions: number;
  triage_notice: string;
}

export interface DetectionMethod {
  method_id: string;
  version: string;
  status: "deterministic" | "experimental" | "validated" | "retired";
  description: string;
  training_data?: string | null;
  validation_reference?: string | null;
  approved_by?: string | null;
  limitations: string[];
  created_at: string;
}

