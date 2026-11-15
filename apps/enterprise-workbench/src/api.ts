import {
  AuditTimelineItem,
  AuditVerification,
  CaseDetail,
  CaseNote,
  CaseSummary,
  ClosureProposal,
  DataContractResponse,
  Persona,
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
};
