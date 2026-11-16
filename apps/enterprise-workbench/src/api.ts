import {
  AuditTimelineItem,
  AuditVerification,
  BehavioralAnomaly,
  BehavioralProfile,
  CaseDetail,
  CaseNote,
  CaseSummary,
  ClosureProposal,
  Connector,
  ConnectorHealth,
  CorrelateCaseResponse,
  CorrelationSignal,
  DataContractResponse,
  DetectionMethod,
  EvidenceContradiction,
  IntegrationJob,
  IntelligenceEvent,
  InvestigationBundle,
  InvestigationHypothesis,
  InvestigationPriority,
  Persona,
  QualityAssessment,
  ReconciliationReport,
  ReconstructionBundle,
  Relationship,
  RevealRequest,
  SimulationApproval,
  SimulationRun,
  SimulationStrategy,
  CaseOutcome,
  WorkbenchOverview,
  CaseFingerprint,
  CaseSimilarity,
  InstitutionalPattern,
  MemoryOverview,
  PatternEvaluation,
  PatternMatch,
  PatternVersion,
  EntityLinkCandidate,
  EntityLinkReview,
  EvidenceSubgraph,
  FindingEvidenceSubgraph,
  NetworkAnalysisResult,
  NetworkAnalysisRun,
  NetworkEdge,
  NetworkNode,
  NetworkPatternFinding,
  NetworkSnapshot,
  ShortestPathResult,
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

  getBehavioralProfile: (subjectType: string, subjectId: string): Promise<BehavioralProfile> =>
    request<BehavioralProfile>(`/api/enterprise/v1/baselines/profiles/${encodeURIComponent(subjectType)}/${encodeURIComponent(subjectId)}`),

  evaluateObservation: (
    subjectType: string,
    subjectId: string,
    payload: {
      dimension: string;
      observed_value: number;
      case_id?: string;
      historical_samples?: number[];
      observation_context?: Record<string, unknown>;
    }
  ): Promise<BehavioralAnomaly> =>
    request<BehavioralAnomaly>(`/api/enterprise/v1/baselines/profiles/${encodeURIComponent(subjectType)}/${encodeURIComponent(subjectId)}/evaluate`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  listAnomalies: (params?: { subject_id?: string; case_id?: string; limit?: number }): Promise<BehavioralAnomaly[]> => {
    const sp = new URLSearchParams();
    if (params?.subject_id) sp.append("subject_id", params.subject_id);
    if (params?.case_id) sp.append("case_id", params.case_id);
    if (params?.limit) sp.append("limit", params.limit.toString());
    const query = sp.toString() ? `?${sp.toString()}` : "";
    return request<BehavioralAnomaly[]>(`/api/enterprise/v1/baselines/anomalies${query}`);
  },

  getCasePriority: (caseId: string): Promise<InvestigationPriority> =>
    request<InvestigationPriority>(`/api/enterprise/v1/baselines/cases/${encodeURIComponent(caseId)}/priority`),

  listDetectionMethods: (): Promise<DetectionMethod[]> =>
    request<DetectionMethod[]>("/api/enterprise/v1/baselines/governance/methods"),

  getCaseReconstruction: (caseId: string): Promise<ReconstructionBundle> =>
    request<ReconstructionBundle>(`/api/enterprise/v1/reconstruction/cases/${encodeURIComponent(caseId)}`),

  reconstructCase: (caseId: string): Promise<ReconstructionBundle> =>
    request<ReconstructionBundle>(`/api/enterprise/v1/reconstruction/cases/${encodeURIComponent(caseId)}/reconstruct`, {
      method: "POST",
    }),

  resolveContradiction: (caseId: string, contradictionId: string, resolutionNote: string): Promise<EvidenceContradiction> =>
    request<EvidenceContradiction>(`/api/enterprise/v1/reconstruction/cases/${encodeURIComponent(caseId)}/contradictions/${encodeURIComponent(contradictionId)}/resolve`, {
      method: "POST",
      body: JSON.stringify({ resolution_note: resolutionNote }),
    }),

  // Phase 8: Counterfactual Investigation Simulator
  listSimulationStrategies: (): Promise<SimulationStrategy[]> =>
    request<SimulationStrategy[]>("/api/enterprise/v1/simulation/strategies"),

  getSimulationStrategy: (strategyId: string, version?: number): Promise<SimulationStrategy> => {
    const q = version ? `?version=${version}` : "";
    return request<SimulationStrategy>(`/api/enterprise/v1/simulation/strategies/${encodeURIComponent(strategyId)}${q}`);
  },

  createSimulationStrategy: (payload: {
    strategy_id: string;
    title: string;
    description?: string;
    rules_enabled: string[];
    parameters?: Record<string, unknown>;
    min_severity?: string;
    min_confidence?: number;
  }): Promise<SimulationStrategy> =>
    request<SimulationStrategy>("/api/enterprise/v1/simulation/strategies", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  listCaseOutcomes: (): Promise<CaseOutcome[]> =>
    request<CaseOutcome[]>("/api/enterprise/v1/simulation/labels"),

  adjudicateCaseOutcome: (payload: {
    case_id: string;
    label: string;
    first_fraud_event_time?: string | null;
    notes?: string | null;
  }): Promise<CaseOutcome> =>
    request<CaseOutcome>("/api/enterprise/v1/simulation/labels", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  executeSimulationRun: (payload: {
    strategy_id: string;
    strategy_version?: number;
    baseline_strategy_id?: string;
    baseline_strategy_version?: number;
    simulation_cutoff?: string;
    cohort_case_ids?: string[];
  }): Promise<SimulationRun> =>
    request<SimulationRun>("/api/enterprise/v1/simulation/runs", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  listSimulationRuns: (): Promise<SimulationRun[]> =>
    request<SimulationRun[]>("/api/enterprise/v1/simulation/runs"),

  getSimulationRun: (simulationId: string): Promise<SimulationRun> =>
    request<SimulationRun>(`/api/enterprise/v1/simulation/runs/${encodeURIComponent(simulationId)}`),

  requestStrategyApproval: (payload: {
    strategy_id: string;
    strategy_version?: number;
    request_rationale: string;
    simulation_run_id?: string;
  }): Promise<SimulationApproval> =>
    request<SimulationApproval>("/api/enterprise/v1/simulation/approvals/request", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  reviewStrategyApproval: (
    approvalId: string,
    payload: { decision: "approved" | "rejected"; notes?: string }
  ): Promise<SimulationApproval> =>
    request<SimulationApproval>(`/api/enterprise/v1/simulation/approvals/${encodeURIComponent(approvalId)}/review`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  listStrategyApprovals: (): Promise<SimulationApproval[]> =>
    request<SimulationApproval[]>("/api/enterprise/v1/simulation/approvals"),

  // Phase 9: Fraud DNA & Institutional Memory
  getMemoryOverview: (): Promise<MemoryOverview> =>
    request<MemoryOverview>("/api/enterprise/v1/memory/overview"),

  discoverPatterns: (minSupport: number = 2): Promise<InstitutionalPattern[]> =>
    request<InstitutionalPattern[]>(`/api/enterprise/v1/memory/patterns/discover?min_support=${minSupport}`, {
      method: "POST",
    }),

  createCandidatePattern: (payload: {
    pattern_id: string;
    title: string;
    description: string;
    feature_signature: Record<string, string>;
    confirmed_fraud_case_ids?: string[];
    confirmed_legitimate_case_ids?: string[];
    independent_source_systems?: string[];
    control_weaknesses?: string[];
    limitations?: string[];
  }): Promise<InstitutionalPattern> =>
    request<InstitutionalPattern>("/api/enterprise/v1/memory/patterns/candidates", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  listPatterns: (status?: string): Promise<InstitutionalPattern[]> => {
    const q = status ? `?status=${encodeURIComponent(status)}` : "";
    return request<InstitutionalPattern[]>(`/api/enterprise/v1/memory/patterns${q}`);
  },

  getPattern: (patternId: string): Promise<InstitutionalPattern> =>
    request<InstitutionalPattern>(`/api/enterprise/v1/memory/patterns/${encodeURIComponent(patternId)}`),

  evaluatePattern: (patternId: string): Promise<PatternEvaluation> =>
    request<PatternEvaluation>(`/api/enterprise/v1/memory/patterns/${encodeURIComponent(patternId)}/evaluate`),

  reviewPattern: (
    patternId: string,
    payload: { action: string; rationale: string }
  ): Promise<InstitutionalPattern> =>
    request<InstitutionalPattern>(`/api/enterprise/v1/memory/patterns/${encodeURIComponent(patternId)}/review`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  listPatternVersions: (patternId: string): Promise<PatternVersion[]> =>
    request<PatternVersion[]>(`/api/enterprise/v1/memory/patterns/${encodeURIComponent(patternId)}/versions`),

  getCaseFingerprint: (caseId: string, refresh: boolean = false): Promise<CaseFingerprint> =>
    request<CaseFingerprint>(`/api/enterprise/v1/memory/cases/${encodeURIComponent(caseId)}/fingerprint?refresh=${refresh}`),

  getSimilarHistoricalCases: (caseId: string, limit: number = 10, minCoverage: number = 0.1): Promise<CaseSimilarity[]> =>
    request<CaseSimilarity[]>(`/api/enterprise/v1/memory/cases/${encodeURIComponent(caseId)}/similar?limit=${limit}&min_coverage=${minCoverage}`),

  matchCasePatterns: (caseId: string, minCoverage: number = 0.1): Promise<PatternMatch[]> =>
    request<PatternMatch[]>(`/api/enterprise/v1/memory/cases/${encodeURIComponent(caseId)}/patterns?min_coverage=${minCoverage}`),

  // Phase 10: Network Intelligence & Fraud Graphs
  expandNeighborhood: (payload: {
    seed_nodes: string[];
    max_depth?: number;
    max_nodes?: number;
    max_edges?: number;
    minimum_confidence?: number;
    include_shared_attributes?: boolean;
    direction?: string;
    as_of?: string;
  }): Promise<EvidenceSubgraph> =>
    request<EvidenceSubgraph>("/api/enterprise/v1/network/expand", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  findShortestPath: (payload: {
    source_key: string;
    target_key: string;
    max_depth?: number;
    minimum_confidence?: number;
    include_shared_attributes?: boolean;
  }): Promise<ShortestPathResult> =>
    request<ShortestPathResult>("/api/enterprise/v1/network/path", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  runNetworkAnalysis: (payload: {
    seed_entities: string[];
    case_id?: string;
    max_depth?: number;
    max_nodes?: number;
    max_edges?: number;
    include_shared_attributes?: boolean;
    as_of?: string;
  }): Promise<NetworkAnalysisResult> =>
    request<NetworkAnalysisResult>("/api/enterprise/v1/network/analyze", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  listNetworkFindings: (caseId?: string): Promise<NetworkPatternFinding[]> => {
    const q = caseId ? `?case_id=${encodeURIComponent(caseId)}` : "";
    return request<NetworkPatternFinding[]>(`/api/enterprise/v1/network/findings${q}`);
  },

  getFindingEvidence: (findingId: string): Promise<FindingEvidenceSubgraph> =>
    request<FindingEvidenceSubgraph>(`/api/enterprise/v1/network/findings/${encodeURIComponent(findingId)}`),

  listEntityLinkCandidates: (): Promise<EntityLinkCandidate[]> =>
    request<EntityLinkCandidate[]>("/api/enterprise/v1/network/entity-links"),

  reviewEntityLink: (
    candidateId: string,
    decision: string,
    rationale: string
  ): Promise<EntityLinkReview> =>
    request<EntityLinkReview>(`/api/enterprise/v1/network/entity-links/${encodeURIComponent(candidateId)}/review`, {
      method: "POST",
      body: JSON.stringify({ decision, rationale }),
    }),

  listNetworkSnapshots: (): Promise<NetworkSnapshot[]> =>
    request<NetworkSnapshot[]>("/api/enterprise/v1/network/snapshots"),

  createNetworkSnapshot: (asOf?: string): Promise<NetworkSnapshot> =>
    request<NetworkSnapshot>("/api/enterprise/v1/network/snapshots", {
      method: "POST",
      body: JSON.stringify({ as_of: asOf }),
    }),

  listNetworkAnalysisRuns: (caseId?: string): Promise<NetworkAnalysisRun[]> => {
    const q = caseId ? `?case_id=${encodeURIComponent(caseId)}` : "";
    return request<NetworkAnalysisRun[]>(`/api/enterprise/v1/network/runs${q}`);
  },

  getCaseNetwork: (
    caseId: string,
    maxDepth: number = 2,
    includeSharedAttributes: boolean = false
  ): Promise<EvidenceSubgraph> =>
    request<EvidenceSubgraph>(
      `/api/enterprise/v1/network/cases/${encodeURIComponent(caseId)}?max_depth=${maxDepth}&include_shared_attributes=${includeSharedAttributes}`
    ),

  getNetworkNode: (nodeKey: string): Promise<NetworkNode> =>
    request<NetworkNode>(`/api/enterprise/v1/network/nodes/${encodeURIComponent(nodeKey)}`),

  listNetworkEdges: (
    sourceKey?: string,
    targetKey?: string,
    relationshipType?: string,
    includeSharedAttributes: boolean = false
  ): Promise<NetworkEdge[]> => {
    const params = new URLSearchParams();
    if (sourceKey) params.append("source_key", sourceKey);
    if (targetKey) params.append("target_key", targetKey);
    if (relationshipType) params.append("relationship_type", relationshipType);
    params.append("include_shared_attributes", String(includeSharedAttributes));
    return request<NetworkEdge[]>(`/api/enterprise/v1/network/edges?${params.toString()}`);
  },
};
