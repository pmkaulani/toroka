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

export interface ReconstructionStep {
  sequence: number;
  event_id: string;
  event_type: string;
  event_time: string;
  actor_id?: string | null;
  subject_id?: string | null;
  source_system?: string | null;
  explanation: string;
  evidence_strength: number;
  provenance_ids: string[];
}

export interface StateTransition {
  previous_state: string;
  new_state: string;
  event_id: string;
  explanation: string;
  material_change: boolean;
}

export interface ChangeVector {
  subject_id: string;
  changed_dimensions: string[];
  baseline_dimensions: string[];
  unusual_dimensions: string[];
  explanation: string;
  completeness: number;
}

export interface AttackPathNode {
  node_id: string;
  node_type: string;
  label: string;
}

export interface AttackPathEdge {
  source_id: string;
  target_id: string;
  relationship: string;
  event_ids: string[];
  confidence: number;
}

export interface AttackPath {
  path_id: string;
  nodes: AttackPathNode[];
  edges: AttackPathEdge[];
  confidence: number;
}

export interface EvidenceContradiction {
  contradiction_id: string;
  installation_id: string;
  case_id?: string | null;
  event_a: string;
  event_b: string;
  field: string;
  value_a: string;
  value_b: string;
  severity: "low" | "medium" | "high";
  explanation: string;
  resolution_required: boolean;
  status: string;
  resolved_by?: string | null;
  resolution_note?: string | null;
  created_at: string;
  resolved_at?: string | null;
}

export interface EvidenceCompleteness {
  total_requirements: number;
  satisfied_requirements: number;
  missing_requirements: string[];
  percentage: number;
  evidence_debt: string[];
}

export interface InvestigationScenario {
  scenario_id: string;
  title: string;
  description: string;
  required_evidence: string[];
  supporting_evidence: string[];
  contradicting_evidence: string[];
  missing_evidence: string[];
  relative_support: number;
}

export interface ReconstructionBundle {
  reconstruction_id: string;
  installation_id: string;
  case_id?: string | null;
  title: string;
  start_time: string;
  end_time: string;
  steps: ReconstructionStep[];
  state_transitions: StateTransition[];
  change_vector?: ChangeVector | null;
  attack_path?: AttackPath | null;
  contradictions: EvidenceContradiction[];
  evidence_completeness: EvidenceCompleteness;
  scenarios: InvestigationScenario[];
  unresolved_questions: string[];
  confidence: number;
  created_at: string;
}

// Phase 8: Counterfactual Investigation Simulator Types
export interface SimulationStrategy {
  strategy_id: string;
  version: number;
  installation_id: string;
  title: string;
  description: string;
  rules_enabled: string[];
  parameters: Record<string, unknown>;
  min_severity: string;
  min_confidence: number;
  status: "draft" | "pending_review" | "approved" | "rejected" | "active";
  created_by: string;
  created_at: string;
}

export interface CaseOutcome {
  case_id: string;
  installation_id: string;
  label: "confirmed_fraud" | "confirmed_legitimate" | "inconclusive" | "unlabelled";
  first_fraud_event_time?: string | null;
  adjudicated_at: string;
  adjudicated_by: string;
  notes?: string | null;
}

export interface SimulationMetrics {
  total_cases_evaluated: number;
  true_positives: number;
  false_positives: number;
  true_negatives: number;
  false_negatives: number;
  precision: number;
  recall: number;
  f1_score: number;
  mean_detection_delay_seconds?: number | null;
  median_detection_delay_seconds?: number | null;
  total_alerts: number;
  alerted_cases: number;
  alert_rate: number;
  inconclusive_cases_alerted: number;
  unlabelled_cases_alerted: number;
  labelled_cases: number;
  inconclusive_cases: number;
  unlabelled_cases: number;
  label_coverage_pct: number;
}

export interface MetricsDelta {
  tp_diff: number;
  fp_diff: number;
  fn_diff: number;
  tn_diff: number;
  precision_diff: number;
  recall_diff: number;
  f1_diff: number;
  detection_delay_diff_seconds?: number | null;
  alert_volume_diff: number;
  summary: string;
}

export interface SimulatedDetection {
  detection_id: string;
  strategy_id: string;
  strategy_version: number;
  case_id: string;
  event_id: string;
  detected_at: string;
  rule_name: string;
  severity: string;
  confidence: number;
  explanation: string;
  supporting_event_ids: string[];
}

export interface SimulationRun {
  simulation_id: string;
  installation_id: string;
  strategy_id: string;
  strategy_version: number;
  baseline_strategy_id?: string | null;
  baseline_strategy_version?: number | null;
  executed_by: string;
  executed_at: string;
  simulation_cutoff?: string | null;
  metrics: SimulationMetrics;
  baseline_metrics?: SimulationMetrics | null;
  delta?: MetricsDelta | null;
  total_events_replayed: number;
  delayed_events_filtered: number;
  case_detections: Record<string, SimulatedDetection[]>;
}

export interface SimulationApproval {
  approval_id: string;
  installation_id: string;
  strategy_id: string;
  strategy_version: number;
  requester_subject: string;
  requested_at: string;
  request_rationale: string;
  simulation_run_id?: string | null;
  status: "pending" | "approved" | "rejected";
  reviewer_subject?: string | null;
  reviewed_at?: string | null;
  review_decision?: string | null;
  review_notes?: string | null;
}

// Phase 9: Fraud DNA & Institutional Memory Types

export interface CaseFingerprint {
  case_id: string;
  installation_id: string;
  extractor_version: string;
  features: Record<string, string>;
  source_systems: string[];
  source_coverage: number;
  total_events: number;
  first_event_time?: string | null;
  last_event_time?: string | null;
  control_weaknesses: string[];
  adjudicated_label?: string | null;
  created_at: string;
}

export interface InstitutionalPattern {
  pattern_id: string;
  installation_id: string;
  version: number;
  title: string;
  description: string;
  feature_signature: Record<string, string>;
  confirmed_fraud_case_ids: string[];
  confirmed_legitimate_case_ids: string[];
  independent_source_systems: string[];
  status: "candidate" | "under_review" | "validated" | "suspended" | "retired";
  extractor_version: string;
  control_weaknesses: string[];
  curator_subject: string;
  reviewer_subject?: string | null;
  reviewed_at?: string | null;
  validation_rationale?: string | null;
  limitations: string[];
  created_at: string;
  updated_at?: string | null;
}

export interface PatternEvaluation {
  pattern_id: string;
  version: number;
  eligible_for_review: boolean;
  checks: Record<string, boolean>;
  blockers: string[];
  details: Record<string, unknown>;
}

export interface PatternReview {
  review_id: string;
  pattern_id: string;
  pattern_version: number;
  reviewer_subject: string;
  action: string;
  rationale: string;
  created_at: string;
}

export interface PatternVersion {
  pattern_id: string;
  version: number;
  title: string;
  description: string;
  feature_signature: Record<string, string>;
  status: string;
  changed_by: string;
  change_summary: string;
  created_at: string;
}

export interface FeatureComparison {
  dimension: string;
  current_value: string;
  historical_value: string;
  matched: boolean;
  current_event_ids: string[];
  historical_event_ids: string[];
}

export interface CaseSimilarity {
  current_case_id: string;
  historical_case_id: string;
  similarity_index?: number | null;
  comparison_coverage: number;
  matched_features: string[];
  different_features: string[];
  historical_outcome?: string | null;
  historical_control_weaknesses: string[];
  shared_control_weaknesses: string[];
  summary_explanation: string;
}

export interface PatternMatch {
  pattern_id: string;
  pattern_version: number;
  pattern_title: string;
  pattern_status: string;
  similarity_index?: number | null;
  comparison_coverage: number;
  matched_features: string[];
  different_features: string[];
  control_weaknesses: string[];
  explanation: string;
  confirmed_fraud_cases_count: number;
  confirmed_legitimate_cases_count: number;
}

export interface MemoryOverview {
  adjudicated_case_count: number;
  validated_pattern_count: number;
  candidate_pattern_count: number;
  under_review_pattern_count: number;
  suspended_pattern_count: number;
  retired_pattern_count: number;
  average_source_coverage: number;
  total_fingerprinted_cases: number;
  recent_reviews: PatternReview[];
}

// =============================================================================
// Phase 10: Network Intelligence & Collaborative Fraud Graphs Types
// =============================================================================

export interface NetworkNode {
  installation_id: string;
  node_key: string;
  entity_type: string;
  pseudonymous_label: string;
  attributes: Record<string, unknown>;
  first_seen?: string | null;
  last_seen?: string | null;
}

export interface NetworkEdge {
  installation_id: string;
  edge_id: string;
  source_key: string;
  target_key: string;
  relationship_type: string;
  evidence_basis: "direct_observation" | "derived_relationship" | "shared_attribute";
  event_ids: string[];
  source_record_ids: string[];
  source_systems: string[];
  first_seen?: string | null;
  last_seen?: string | null;
  confidence: number;
  directed: boolean;
  attributes: Record<string, unknown>;
}

export interface EvidenceSubgraph {
  installation_id: string;
  seed_nodes: string[];
  nodes: NetworkNode[];
  edges: NetworkEdge[];
  truncated: boolean;
  truncation_reason?: string | null;
  max_depth_reached: number;
  limitations: string[];
  node_count: number;
  edge_count: number;
}

export interface NetworkPatternFinding {
  pattern_id: string;
  installation_id: string;
  pattern_type:
    | "fan_in"
    | "fan_out"
    | "rapid_pass_through"
    | "multi_hop_movement"
    | "circular_movement"
    | "common_beneficiary"
    | "shared_infrastructure"
    | "dormant_account_activation"
    | "coordinated_account_changes";
  anchor_entity: string;
  related_entities: string[];
  event_ids: string[];
  start_time: string;
  end_time: string;
  detection_time: string;
  explanation: string;
  evidence_limitations: string[];
  alternative_legitimate_explanations: string[];
  supporting_source_systems: string[];
  transaction_ids: string[];
  monetary_total?: string | null;
  currency?: string | null;
  confidence: number;
  pattern_version: string;
}

export interface EntityLinkCandidate {
  candidate_id: string;
  installation_id: string;
  source_entity_key: string;
  target_entity_key: string;
  attribute_type: string;
  attribute_value: string;
  match_type: string;
  status: "SAME_ENTITY_CONFIRMED" | "POSSIBLY_RELATED" | "SHARED_ATTRIBUTE_ONLY" | "RELATIONSHIP_DISPROVEN";
  confidence: number;
  supporting_evidence: Array<Record<string, unknown>>;
  contradicting_evidence: Array<Record<string, unknown>>;
  source_systems: string[];
  first_observed: string;
  last_observed: string;
  reviewed_by?: string | null;
  reviewed_at?: string | null;
  review_rationale?: string | null;
}

export interface EntityLinkReview {
  review_id: string;
  candidate_id: string;
  installation_id: string;
  reviewer_subject: string;
  decision: string;
  rationale: string;
  previous_status: string;
  new_status: string;
  reviewed_at: string;
}

export interface FindingEvidenceSubgraph {
  finding_id: string;
  installation_id: string;
  pattern_type: string;
  anchor_entity: string;
  nodes: NetworkNode[];
  edges: NetworkEdge[];
  supporting_event_ids: string[];
  supporting_transaction_ids: string[];
  supporting_source_systems: string[];
  confidence: number;
  explanation: string;
  limitations: string[];
  alternative_explanations: string[];
  missing_information: string[];
}

export interface NetworkAnalysisResult {
  analysis_id: string;
  installation_id: string;
  case_id?: string | null;
  anchor_entities: string[];
  subgraph: EvidenceSubgraph;
  findings: NetworkPatternFinding[];
  entity_link_candidates: EntityLinkCandidate[];
  source_coverage: number;
  source_systems: string[];
  alternative_explanations: string[];
  missing_evidence: string[];
  institutional_pattern_matches: Array<Record<string, unknown>>;
  executed_at: string;
}

export interface NetworkSnapshot {
  snapshot_id: string;
  installation_id: string;
  as_of: string;
  node_count: number;
  edge_count: number;
  nodes_digest: string;
  edges_digest: string;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface NetworkAnalysisRun {
  run_id: string;
  installation_id: string;
  case_id?: string | null;
  executed_by: string;
  seed_entities: string[];
  findings_count: number;
  nodes_count: number;
  edges_count: number;
  truncated: boolean;
  result_digest: string;
  executed_at: string;
}

export interface ShortestPathResult {
  source_key: string;
  target_key: string;
  found: boolean;
  path_length: number;
  nodes: NetworkNode[];
  edges: NetworkEdge[];
}

// Phase 11: AI Investigation Copilot Types
export interface CopilotThread {
  thread_id: string;
  installation_id: string;
  case_id: string;
  title: string;
  created_by: string;
  is_archived: boolean;
  created_at: string;
  updated_at: string;
}

export interface CopilotEvidenceQuote {
  evidence_id: string;
  quoted_text: string;
}

export interface CopilotGroundedClaim {
  claim_id: string;
  kind: "fact" | "inference" | "unknown" | "recommendation";
  statement: string;
  evidence_ids: string[];
  quotes: CopilotEvidenceQuote[];
  limitations?: string | null;
  investigative_basis?: string | null;
  alternative_explanations: string[];
}

export interface CopilotGroundingReport {
  valid: boolean;
  verified_claims: number;
  rejected_claims: string[];
  rejection_reasons: string[];
}

export interface CopilotMessage {
  message_id: string;
  thread_id: string;
  installation_id: string;
  case_id: string;
  role: "user" | "assistant" | "system";
  content: string;
  task_type?: string | null;
  claims: CopilotGroundedClaim[];
  citations: Array<{ evidence_id: string; quoted_text: string }>;
  tool_calls: Array<Record<string, unknown>>;
  grounding_report?: CopilotGroundingReport | null;
  created_at: string;
}

export interface CopilotReportDraft {
  draft_id: string;
  installation_id: string;
  case_id: string;
  thread_id?: string | null;
  report_type: string;
  title: string;
  content_markdown: string;
  investigator_edits_markdown?: string | null;
  status: "DRAFT" | "INVESTIGATOR_REVIEW" | "ACCEPTED" | "REJECTED";
  evidence_context_hash: string;
  citations: Array<{ evidence_id: string; quoted_text: string }>;
  model_info: Record<string, unknown>;
  review_notes?: string | null;
  reviewed_by?: string | null;
  reviewed_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface CopilotFeedback {
  feedback_id: string;
  message_id: string;
  rating: number;
  feedback_text?: string | null;
  created_by: string;
  created_at: string;
}

export interface CopilotStatus {
  status: string;
  provider: string;
  model: string;
  air_gapped: boolean;
  data_retention_verified: boolean;
  active_tools_count: number;
  allowed_tools: string[];
}

// =============================================================================
// Phase 12 Types: Production Governance, Model Risk & Bank Deployment
// =============================================================================

export interface GovernedComponent {
  component_id: string;
  version: string;
  installation_id: string;
  component_type: string;
  name: string;
  status: "draft" | "validation" | "approved" | "staged" | "active" | "suspended" | "retired";
  risk_tier: "low" | "moderate" | "high" | "critical";
  owner_team: string;
  source_digest: string;
  configuration_digest: string;
  parameters: Record<string, unknown>;
  created_by: string;
  approved_by?: string | null;
  approved_at?: string | null;
  suspended_by?: string | null;
  suspended_at?: string | null;
  retired_by?: string | null;
  retired_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface ValidationMetric {
  name: string;
  value: number;
  threshold?: number | null;
  direction?: string | null;
  result: "pass" | "fail" | "inconclusive";
}

export interface ValidationRun {
  run_id: string;
  installation_id: string;
  component_id: string;
  component_version: string;
  dataset_digest: string;
  configuration_digest: string;
  metrics: ValidationMetric[];
  result: "pass" | "fail" | "inconclusive";
  evaluator: string;
  limitations: string[];
  started_at: string;
  completed_at: string;
  created_at: string;
}

export interface ProductionRelease {
  release_id: string;
  installation_id: string;
  version: string;
  environment: "development" | "validation" | "pilot" | "production";
  status: "draft" | "validated" | "approved" | "staged" | "active" | "rolled_back" | "retired";
  components_manifest: Record<string, string>;
  validation_runs: string[];
  approval_records: string[];
  readiness_gates: Array<Record<string, unknown>>;
  manifest_digest: string;
  signature_bundle?: Record<string, unknown> | null;
  is_digitally_signed?: boolean;
  promoted_by?: string | null;
  promoted_at?: string | null;
  rollback_target_id?: string | null;
  created_by: string;
  created_at: string;
}

export interface SuspensionRecord {
  suspension_id: string;
  installation_id: string;
  component_id: string;
  component_version: string;
  suspended_by: string;
  reason: string;
  incident_id?: string | null;
  is_active: boolean;
  suspended_at: string;
  resumed_by?: string | null;
  resumed_at?: string | null;
  resume_reason?: string | null;
}

export interface GovernanceIncident {
  incident_id: string;
  installation_id: string;
  title: string;
  category: string;
  severity: "low" | "medium" | "high" | "critical";
  status: "triaged" | "contained" | "investigating" | "remediated" | "recovered" | "closed";
  affected_components: string[];
  affected_case_ids: string[];
  detection_source: string;
  detected_at: string;
  contained_at?: string | null;
  resolved_at?: string | null;
  owner: string;
  remediation_notes?: string | null;
  post_incident_review?: string | null;
  created_at: string;
}

export interface DriftRecord {
  drift_id: string;
  installation_id: string;
  drift_type: string;
  component_id: string;
  metric_name: string;
  baseline_value: number;
  observed_value: number;
  threshold: number;
  severity: string;
  recommended_response: string;
  details: Record<string, unknown>;
  detected_at: string;
}

export interface SystemHealthOverview {
  overall_status: "healthy" | "degraded" | "warning" | "critical";
  detection_health: string;
  data_quality_health: string;
  network_health: string;
  copilot_health: string;
  audit_integrity_health: string;
  active_drift_count: number;
  open_incidents_count: number;
  summary_message: string;
}

export interface EvidencePassport {
  passport_id: string;
  installation_id: string;
  finding_id: string;
  case_id: string;
  finding_type: string;
  finding_status: string;
  component_versions: Record<string, string>;
  configuration_digest: string;
  evidence_count: number;
  source_systems: string[];
  detection_time: string;
  earliest_event_time?: string | null;
  evidence_at_detection_count: number;
  delayed_evidence_count: number;
  contradictions_count: number;
  evidence_debt_level: string;
  alternative_explanations: string[];
  validation_result: string;
  human_review_required: boolean;
  passport_digest: string;
  signature_bundle?: Record<string, unknown> | null;
  merkle_proof?: Record<string, unknown> | null;
  is_digitally_signed?: boolean;
  is_verified: boolean;
  created_at: string;
}

export interface GovernedAIProvider {
  provider_id: string;
  installation_id: string;
  provider_name: string;
  model_identifier: string;
  model_version: string;
  hosting_location: string;
  data_retention_policy: string;
  training_on_customer_data_permitted: boolean;
  is_approved: boolean;
  risk_tier: string;
  evaluation_summary: Record<string, unknown>;
  last_evaluated_at?: string | null;
  created_at: string;
  review_status?: string | null;
  registered_by?: string | null;
  approved_by?: string | null;
  approved_at?: string | null;
  review_notes?: string | null;
}

export interface ReadinessAssessment {
  installation_id: string;
  release_version: string;
  overall_status: string;
  is_production_ready: boolean;
  gates: Array<{
    gate_name: string;
    status: string;
    verified_by: string;
    rationale: string;
    evidence_reference?: string | null;
  }>;
  evaluated_at: string;
}

export interface ValidationPackage {
  installation_id: string;
  generated_at: string;
  release_version: string;
  components_count: number;
  active_detectors: string[];
  validation_runs_count: number;
  readiness_status: string;
  open_incidents_count: number;
  active_suspensions_count: number;
  executive_summary: string;
  document_sections: {
    model_inventory: Array<Record<string, unknown>>;
    validation_summary: Array<Record<string, unknown>>;
    controls_and_governance: Record<string, unknown>;
  };
}

export interface QuantitativeDriftEvaluation {
  evaluation_id: string;
  installation_id: string;
  component_id: string;
  component_version: string;
  psi_score: number;
  psi_severity: "STABLE" | "MODERATE" | "SIGNIFICANT";
  requires_mitigation: boolean;
  ks_statistic: number;
  ks_p_value: number;
  ks_drift_detected: boolean;
  wasserstein_distance: number;
  fairness_compliant: boolean;
  is_compliant: boolean;
  governance_findings: string[];
  evaluation_details: Record<string, unknown>;
  evaluated_by: string;
  created_at: string;
}

export interface ChampionChallengerRun {
  run_id: string;
  installation_id: string;
  component_id: string;
  champion_version: string;
  challenger_version: string;
  decision: string;
  is_promotable: boolean;
  fdr_delta: number;
  f1_ratio: number;
  latency_p95_delta_ms: number;
  reasons: string[];
  champion_metrics: Record<string, unknown>;
  challenger_metrics: Record<string, unknown>;
  evaluated_by: string;
  created_at: string;
}

export interface SignatureBundle {
  algorithm: string;
  signature_hex: string;
  public_key_pem: string;
  key_id: string;
  signed_at: string;
}

export interface CustodyEvent {
  event_id: string;
  timestamp: string;
  actor_subject: string;
  actor_role: string;
  action: string;
  source_hash: string;
  destination_hash: string;
  notes?: string;
}

export interface Section106BCertificate {
  certificate_id: string;
  statutory_framework: string;
  certifier_name: string;
  certifier_designation: string;
  certifier_organization: string;
  device_identification: string;
  operating_condition_statement: string;
  hash_algorithm: string;
  merkle_root_hash: string;
  certified_at: string;
  declaration_text: string;
}

export interface ForensicDossier {
  dossier_id: string;
  installation_id: string;
  case_id: string;
  title: string;
  incident_type: string;
  fraud_loss_amount: number;
  currency: string;
  examiner_subject: string;
  examiner_role: string;
  case_summary: string;
  attack_path_summary: Record<string, unknown>;
  identified_mule_nodes: Array<Record<string, unknown>>;
  evidence_records: Array<Record<string, unknown>>;
  chain_of_custody: CustodyEvent[];
  section_106b_certificate?: Section106BCertificate | null;
  dossier_digest: string;
  signature_bundle?: SignatureBundle | null;
  is_digitally_signed: boolean;
  is_verified: boolean;
  status: string;
  created_at: string;
}

export interface InflightPaymentEvaluation {
  end_to_end_id: string;
  decision: "ALLOW" | "STEP_UP_AUTH" | "QUARANTINE_HOLD" | "BLOCK" | "DELAY_SETTLEMENT_15M" | "INFLOW_ONLY" | "RESTRICT_NON_COUNTER";
  risk_score: number;
  risk_tier: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  triggered_rules: string[];
  recommended_action: string;
  integration_mode?: string;
  latency_ms: number;
  evaluated_at: string;
  cop_status?: string | null;
  cop_match_score?: number | null;
  telecom_call_status?: string | null;
  telecom_coercion_score?: number | null;
  is_telecom_coerced?: boolean;
  is_federated_mule?: boolean;
  federated_mule_tier?: string | null;
}

export interface CopVerifyRequest {
  intended_name: string;
  registered_name: string;
  account_number: string;
  account_type?: "PERSONAL" | "BUSINESS";
  clearing_rail?: string;
  bank_bic?: string;
  inquiry_id?: string;
}

export interface CopVerifyResponse {
  inquiry_id: string;
  status: "MATCH" | "CLOSE_MATCH" | "NO_MATCH";
  match_score: number;
  intended_name_normalized: string;
  registered_name_normalized: string;
  suggested_name?: string | null;
  reason_code: string;
  advisory_message: string;
  inquiry_digest: string;
  verified_at: string;
}

export interface SemanticVerifyResponse {
  is_valid: boolean;
  verification_scope: string;
  methodology: string;
  total_claims: number;
  entailed_claims: number;
  contradicted_claims: number;
  numeric_mismatches: number;
  ungrounded_claims: number;
  evaluations: Array<{
    claim_id: string;
    statement: string;
    kind: string;
    status: string;
    reasons: string[];
    confidence: number;
  }>;
}

export interface TrustedSignerRecord {
  key_id: string;
  installation_id: string;
  algorithm: string;
  purpose: string;
  security_level: string;
  is_active: boolean;
  is_revoked?: boolean;
  revocation_reason?: string | null;
}

export interface TelecomSignalRequest {
  msisdn: string;
  carrier?: "SAFARICOM" | "AIRTEL" | "TELKOM" | "UNKNOWN";
  query_id?: string;
  simulated_call_status?: "IDLE" | "CALL_IN_PROGRESS" | "RECENT_CALL" | "UNKNOWN";
  simulated_call_duration_seconds?: number;
  simulated_sim_swap_age_hours?: number;
}

export interface TelecomSignalResponse {
  query_id: string;
  msisdn: string;
  carrier: string;
  call_status: "IDLE" | "CALL_IN_PROGRESS" | "RECENT_CALL" | "UNKNOWN" | string;
  call_duration_seconds: number;
  sim_swap_status: string;
  sim_swap_age_hours?: number | null;
  scam_signal_score: number;
  is_high_coercion_risk: boolean;
  coercion_indicators: string[];
  advisory_action: string;
  statutory_warning: string;
  query_digest: string;
  queried_at: string;
}

export interface FederatedMuleEntry {
  entry_id: string;
  installation_id: string;
  entity_type: "BANK_ACCOUNT" | "MSISDN" | "NATIONAL_ID" | "PAYBILL_TILL" | string;
  blinded_token: string;
  cleartext_preview: string;
  severity_tier: "SUSPECT_MULE" | "CORROBORATED_MULE" | "CONFIRMED_SYNDICATE_CONTROLLER" | string;
  originating_bank_bic: string;
  reason_code: string;
  dossier_reference?: string | null;
  status: "ACTIVE" | "CONTESTED" | "EXPUNGED" | string;
  registered_by?: string | null;
  registered_at: string;
  expires_at?: string | null;
}

export interface QueryFederatedMuleResponse {
  is_match: boolean;
  blinded_token: string;
  cleartext_preview: string;
  entity_type: string;
  severity_tier?: string | null;
  originating_bank_bic?: string | null;
  reason_code?: string | null;
  dossier_reference?: string | null;
  status: string;
  registered_at?: string | null;
  expires_at?: string | null;
  recommended_action: string;
}

// Phase 14.3 Multi-Tiered Mule Tracing & Graph Cascade
export interface MuleCascadeNode {
  node_key: string;
  tier_level: number;
  tier_name: string;
  bank_bic: string;
  account_name?: string | null;
  total_inflow: string;
  total_outflow: string;
  retained_balance_estimate: string;
  velocity_minutes: number;
  dispersion_ratio: number;
  risk_score: number;
  recommended_directive: string;
  directive_status: string;
  first_inflow_time?: string | null;
  last_outflow_time?: string | null;
}

export interface MuleCascadeEdge {
  edge_id: string;
  source_node: string;
  target_node: string;
  amount: string;
  currency: string;
  timestamp: string;
  payment_rail: string;
  transaction_id: string;
  hop_number: number;
  transfer_delay_minutes: number;
}

export interface CascadeDirective {
  directive_id: string;
  node_key: string;
  tier_level: number;
  bank_bic: string;
  is_internal: boolean;
  directive_type: string;
  target_amount: string;
  currency: string;
  status: "PENDING" | "EXECUTED" | "REJECTED" | string;
  recommended_action: string;
  executed_by?: string | null;
  executed_at?: string | null;
  justification?: string | null;
  camt056_xml?: string | null;
}

export interface MuleCascadeTrace {
  trace_id: string;
  installation_id: string;
  root_account: string;
  root_transaction_id?: string | null;
  root_fraud_amount: string;
  currency: string;
  max_depth_reached: number;
  nodes: MuleCascadeNode[];
  edges: MuleCascadeEdge[];
  total_nodes_identified: number;
  total_frozen_or_held_amount: string;
  recovery_potential_ratio: number;
  created_at: string;
  status: string;
  directives: CascadeDirective[];
}

export interface TriggerMuleCascadeTracePayload {
  root_account: string;
  root_fraud_amount: string | number;
  currency?: string;
  root_transaction_id?: string | null;
  anchor_time?: string | null;
  max_hops?: number;
  time_window_hours?: number;
  local_bank_bic?: string;
  transfers?: Array<Record<string, unknown>>;
  account_metadata?: Record<string, Record<string, unknown>>;
}

export interface ExecuteCascadeDirectivePayload {
  directive_id: string;
  action: "EXECUTE_LOCAL_HOLD" | "DISPATCH_CAMT056" | "REJECT";
  justification?: string;
}

export interface ExecuteCascadeDirectiveResponse {
  directive_id: string;
  trace_id: string;
  status: string;
  action_taken: string;
  camt056_xml?: string | null;
  executed_at: string;
}







