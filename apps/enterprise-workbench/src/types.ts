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
