import {
  AuditTimelineItem,
  AuditVerification,
  CaseDetail,
  CaseNote,
  CaseSummary,
  ClosureProposal,
  Connector,
  ConnectorHealth,
  CorrelateCaseResponse,
  CorrelationSignal,
  DataContractResponse,
  IntegrationJob,
  IntelligenceEvent,
  InvestigationBundle,
  InvestigationHypothesis,
  Persona,
  QualityAssessment,
  ReconciliationReport,
  Relationship,
  RevealRequest,
  WorkbenchOverview,
} from "./types";

export const BANK_PERSONAS: Persona[] = [
  {
    id: "inv-alice",
    name: "Alice M.",
    role: "investigator",
    title: "Senior Fraud Investigator",
    badge: "Case Maker",
  },
  {
    id: "auth-bob",
    name: "Robert (Bob) K.",
    role: "authoriser",
    title: "Head of Financial Crime Compliance",
    badge: "Governance Checker",
  },
  {
    id: "aud-carol",
    name: "Carol N.",
    role: "auditor",
    title: "Internal Audit & Assurance",
    badge: "Read-Only Assessor",
  },
  {
    id: "stew-dave",
    name: "David O.",
    role: "data_steward",
    title: "Core Banking Data Steward",
    badge: "Contract & Feeds",
  },
  {
    id: "admin-eve",
    name: "Eve S.",
    role: "system_administrator",
    title: "SecOps / Platform Engineer",
    badge: "Platform Admin",
  },
];

let currentPersona: Persona = BANK_PERSONAS[0];

export function getCurrentPersona(): Persona {
  return currentPersona;
}

export function setCurrentPersona(persona: Persona): void {
  currentPersona = persona;
}

function getHeaders(): HeadersInit {
  return {
    "Content-Type": "application/json",
    "X-Dev-User": currentPersona.id,
    "X-Dev-Roles": currentPersona.role,
    "X-Correlation-ID": `wb-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
  };
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = endpoint.startsWith("http") ? endpoint : endpoint;
  const res = await fetch(url, {
    ...options,
    headers: {
      ...getHeaders(),
      ...(options.headers || {}),
    },
  });

  if (!res.ok) {
    let errorDetail = `HTTP ${res.status}: ${res.statusText}`;
    try {
      const errJson = await res.json();
      if (errJson.detail) {
        errorDetail = typeof errJson.detail === "string" ? errJson.detail : JSON.stringify(errJson.detail);
      }
    } catch {
      // ignore
    }
    throw new Error(errorDetail);
  }

  return res.json() as Promise<T>;
}

export const api = {
  getOverview: (): Promise<WorkbenchOverview> =>
    request<WorkbenchOverview>("/api/enterprise/v1/overview"),

  listCases: (status?: string): Promise<{ total: number; items: CaseSummary[] }> => {
    const q = status ? `?status=${encodeURIComponent(status)}` : "";
    return request<{ total: number; items: CaseSummary[] }>(`/api/enterprise/v1/cases${q}`);
  },

  getCase: (caseId: string): Promise<CaseDetail> =>
    request<CaseDetail>(`/api/enterprise/v1/cases/${encodeURIComponent(caseId)}`),

  listCaseNotes: (caseId: string): Promise<CaseNote[]> =>
    request<CaseNote[]>(`/api/enterprise/v1/cases/${encodeURIComponent(caseId)}/notes`),

  addCaseNote: (caseId: string, body: string): Promise<CaseNote> =>
    request<CaseNote>(`/api/enterprise/v1/cases/${encodeURIComponent(caseId)}/notes`, {
      method: "POST",
      body: JSON.stringify({ body }),
    }),

  listCaseClosureProposals: (caseId: string): Promise<ClosureProposal[]> =>
    request<ClosureProposal[]>(`/api/enterprise/v1/cases/${encodeURIComponent(caseId)}/closure-proposals`),

  proposeClosure: (
    caseId: string,
    payload: {
      disposition: string;
      closing_note: string;
      alternatives_considered: string;
      expected_case_version: number;
    }
  ): Promise<ClosureProposal> =>
    request<ClosureProposal>(`/api/enterprise/v1/cases/${encodeURIComponent(caseId)}/propose-closure`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  listPendingClosureProposals: (): Promise<ClosureProposal[]> =>
    request<ClosureProposal[]>("/api/enterprise/v1/closure-proposals"),

  reviewClosureProposal: (
    proposalId: string,
    payload: { approve: boolean; review_note?: string }
  ): Promise<ClosureProposal> =>
    request<ClosureProposal>(`/api/enterprise/v1/closure-proposals/${encodeURIComponent(proposalId)}/review`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  createRevealRequest: (
    caseId: string,
    payload: { pseudonym: string; reason: string; ttl_hours?: number }
  ): Promise<RevealRequest> =>
    request<RevealRequest>(`/api/enterprise/v1/cases/${encodeURIComponent(caseId)}/reveal-requests`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  listPendingReveals: (): Promise<RevealRequest[]> =>
    request<RevealRequest[]>("/api/enterprise/v1/reveal-requests"),

  approveReveal: (requestId: string): Promise<RevealRequest> =>
    request<RevealRequest>(`/api/enterprise/v1/reveal-requests/${encodeURIComponent(requestId)}/approve`, {
      method: "POST",
    }),

  rejectReveal: (requestId: string, rejectionReason: string): Promise<RevealRequest> =>
    request<RevealRequest>(`/api/enterprise/v1/reveal-requests/${encodeURIComponent(requestId)}/reject`, {
      method: "POST",
      body: JSON.stringify({ rejection_reason: rejectionReason }),
    }),

  // Deliberate consumption: plaintext identity returned once and must NEVER be stored in state/cache
  consumeReveal: async (
    requestId: string
  ): Promise<{ request_id: string; pseudonym: string; plaintext_identity: string; consumed_at: string }> => {
    return request<{ request_id: string; pseudonym: string; plaintext_identity: string; consumed_at: string }>(
      `/api/enterprise/v1/reveal-requests/${encodeURIComponent(requestId)}/consume`,
      { method: "POST" }
    );
  },

  getCaseTimeline: (caseId: string): Promise<AuditTimelineItem[]> =>
    request<AuditTimelineItem[]>(`/api/enterprise/v1/cases/${encodeURIComponent(caseId)}/timeline`),

  verifyAuditChain: (): Promise<AuditVerification> =>
    request<AuditVerification>("/api/enterprise/v1/audit/verify"),

  listAuditRecords: (): Promise<AuditTimelineItem[]> =>
    request<AuditTimelineItem[]>("/api/enterprise/v1/audit/records"),

  getDataContract: (): Promise<DataContractResponse> =>
    request<DataContractResponse>("/data-contract"),

  listConnectors: (): Promise<Connector[]> =>
    request<Connector[]>("/api/enterprise/v1/integrations/connectors"),

  getConnectorHealth: (connectorId: string): Promise<ConnectorHealth> =>
    request<ConnectorHealth>(`/api/enterprise/v1/integrations/connectors/${encodeURIComponent(connectorId)}/health`),

  triggerConnectorSync: (
    connectorId: string,
    payload: { batch_size?: number; max_batches?: number } = {}
  ): Promise<{
    job_id: string;
    connector_id: string;
    status: string;
    records_received: number;
    records_accepted: number;
    records_duplicates: number;
    records_corrected: number;
  }> =>
    request(`/api/enterprise/v1/integrations/connectors/${encodeURIComponent(connectorId)}/sync`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  setConnectorState: (connectorId: string, enabled: boolean): Promise<Connector> =>
    request<Connector>(
      `/api/enterprise/v1/integrations/connectors/${encodeURIComponent(connectorId)}/${enabled ? "enable" : "disable"}`,
      { method: "POST" }
    ),

  listIntegrationJobs: (connectorId?: string): Promise<IntegrationJob[]> => {
    const q = connectorId ? `?connector_id=${encodeURIComponent(connectorId)}` : "";
    return request<IntegrationJob[]>(`/api/enterprise/v1/integrations/jobs${q}`);
  },

  runReconciliation: (payload: {
    connector_id: string;
    expected_source_count?: number;
    window_start?: string;
    window_end?: string;
  }): Promise<ReconciliationReport> =>
    request<ReconciliationReport>("/api/enterprise/v1/integrations/reconciliation", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  getQualityAssessment: (connectorId?: string): Promise<QualityAssessment> => {
    const q = connectorId ? `?connector_id=${encodeURIComponent(connectorId)}` : "";
    return request<QualityAssessment>(`/api/enterprise/v1/integrations/quality${q}`);
  },

  getCaseInvestigation: (caseId: string): Promise<InvestigationBundle> =>
    request<InvestigationBundle>(`/api/enterprise/v1/intelligence/cases/${encodeURIComponent(caseId)}/investigation`),

  correlateCase: (
    caseId: string,
    payload: { window_before_minutes?: number; window_after_minutes?: number } = {}
  ): Promise<CorrelateCaseResponse> =>
    request<CorrelateCaseResponse>(`/api/enterprise/v1/intelligence/cases/${encodeURIComponent(caseId)}/correlate`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  saveCaseHypothesis: (
    caseId: string,
    payload: {
      hypothesis_id: string;
      title: string;
      description: string;
      status: string;
      supporting_signal_ids?: string[];
      contradicting_signal_ids?: string[];
      confidence?: number;
      investigator_note?: string;
    }
  ): Promise<InvestigationHypothesis> =>
    request<InvestigationHypothesis>(`/api/enterprise/v1/intelligence/cases/${encodeURIComponent(caseId)}/hypotheses`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  listCaseHypotheses: (caseId: string): Promise<InvestigationHypothesis[]> =>
    request<InvestigationHypothesis[]>(`/api/enterprise/v1/intelligence/cases/${encodeURIComponent(caseId)}/hypotheses`),

  getCaseRelationships: (caseId: string): Promise<Relationship[]> =>
    request<Relationship[]>(`/api/enterprise/v1/intelligence/cases/${encodeURIComponent(caseId)}/relationships`),

  getIntelligenceTimeline: (caseId: string): Promise<IntelligenceEvent[]> =>
    request<IntelligenceEvent[]>(`/api/enterprise/v1/intelligence/cases/${encodeURIComponent(caseId)}/timeline`),

  listCorrelationSignals: (limit: number = 50): Promise<CorrelationSignal[]> =>
    request<CorrelationSignal[]>(`/api/enterprise/v1/intelligence/signals?limit=${limit}`),
};
