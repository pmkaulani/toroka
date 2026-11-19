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
  CopilotFeedback,
  CopilotMessage,
  CopilotReportDraft,
  CopilotStatus,
  CopilotThread,
  GovernedComponent,
  ValidationRun,
  ProductionRelease,
  SuspensionRecord,
  GovernanceIncident,
  DriftRecord,
  SystemHealthOverview,
  EvidencePassport,
  GovernedAIProvider,
  ReadinessAssessment,
  ValidationPackage,
  QuantitativeDriftEvaluation,
  ChampionChallengerRun,
  ForensicDossier,
  InflightPaymentEvaluation,
  CopVerifyResponse,
  TelecomSignalResponse,
  FederatedMuleEntry,
  QueryFederatedMuleResponse,
  MuleCascadeTrace,
  TriggerMuleCascadeTracePayload,
  ExecuteCascadeDirectivePayload,
  ExecuteCascadeDirectiveResponse,
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

  // Phase 11: AI Investigation Copilot
  getCopilotStatus: (): Promise<CopilotStatus> =>
    request<CopilotStatus>("/api/enterprise/v1/copilot/status"),

  createCopilotThread: (caseId: string, title: string = "Investigation Thread"): Promise<CopilotThread> =>
    request<CopilotThread>("/api/enterprise/v1/copilot/threads", {
      method: "POST",
      body: JSON.stringify({ case_id: caseId, title }),
    }),

  listCopilotThreads: (caseId: string): Promise<CopilotThread[]> =>
    request<CopilotThread[]>(`/api/enterprise/v1/copilot/threads?case_id=${encodeURIComponent(caseId)}`),

  getCopilotThread: (threadId: string): Promise<CopilotThread> =>
    request<CopilotThread>(`/api/enterprise/v1/copilot/threads/${encodeURIComponent(threadId)}`),

  archiveCopilotThread: (threadId: string): Promise<void> =>
    request<void>(`/api/enterprise/v1/copilot/threads/${encodeURIComponent(threadId)}`, {
      method: "DELETE",
    }),

  sendCopilotMessage: (threadId: string, content: string): Promise<CopilotMessage> =>
    request<CopilotMessage>(`/api/enterprise/v1/copilot/threads/${encodeURIComponent(threadId)}/messages`, {
      method: "POST",
      body: JSON.stringify({ content }),
    }),

  listCopilotMessages: (threadId: string): Promise<CopilotMessage[]> =>
    request<CopilotMessage[]>(`/api/enterprise/v1/copilot/threads/${encodeURIComponent(threadId)}/messages`),

  getMessageCitations: (messageId: string): Promise<Array<{ evidence_id: string; quoted_text: string }>> =>
    request<Array<{ evidence_id: string; quoted_text: string }>>(`/api/enterprise/v1/copilot/messages/${encodeURIComponent(messageId)}/citations`),

  generateReportDraft: (payload: {
    case_id: string;
    thread_id?: string;
    report_type?: string;
    title?: string;
  }): Promise<CopilotReportDraft> =>
    request<CopilotReportDraft>("/api/enterprise/v1/copilot/reports/generate", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  listReportDrafts: (caseId: string): Promise<CopilotReportDraft[]> =>
    request<CopilotReportDraft[]>(`/api/enterprise/v1/copilot/reports?case_id=${encodeURIComponent(caseId)}`),

  getReportDraft: (draftId: string): Promise<CopilotReportDraft> =>
    request<CopilotReportDraft>(`/api/enterprise/v1/copilot/reports/${encodeURIComponent(draftId)}`),

  updateReportDraft: (draftId: string, editsMarkdown: string): Promise<CopilotReportDraft> =>
    request<CopilotReportDraft>(`/api/enterprise/v1/copilot/reports/${encodeURIComponent(draftId)}`, {
      method: "PUT",
      body: JSON.stringify({ investigator_edits_markdown: editsMarkdown }),
    }),

  reviewReportDraft: (draftId: string, decision: string, notes?: string): Promise<CopilotReportDraft> =>
    request<CopilotReportDraft>(`/api/enterprise/v1/copilot/reports/${encodeURIComponent(draftId)}/review`, {
      method: "POST",
      body: JSON.stringify({ decision, notes }),
    }),

  submitCopilotFeedback: (messageId: string, rating: number, feedbackText?: string): Promise<CopilotFeedback> =>
    request<CopilotFeedback>(`/api/enterprise/v1/copilot/messages/${encodeURIComponent(messageId)}/feedback`, {
      method: "POST",
      body: JSON.stringify({ rating, feedback_text: feedbackText }),
    }),

  // =========================================================================
  // Phase 12: Production Governance, Model Risk & Bank Deployment
  // =========================================================================

  listGovernedComponents: (params?: { component_type?: string; status?: string }): Promise<GovernedComponent[]> => {
    const q = new URLSearchParams();
    if (params?.component_type) q.set("component_type", params.component_type);
    if (params?.status) q.set("status", params.status);
    const qs = q.toString() ? `?${q.toString()}` : "";
    return request<GovernedComponent[]>(`/api/enterprise/v1/governance/components${qs}`);
  },

  registerGovernedComponent: (payload: {
    component_id: string;
    version: string;
    component_type: string;
    name: string;
    risk_tier: string;
    owner_team: string;
    source_digest: string;
    configuration_digest: string;
    parameters?: Record<string, unknown>;
  }): Promise<GovernedComponent> =>
    request<GovernedComponent>("/api/enterprise/v1/governance/components", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  getGovernedComponent: (componentId: string, version: string): Promise<GovernedComponent> =>
    request<GovernedComponent>(`/api/enterprise/v1/governance/components/${encodeURIComponent(componentId)}/${encodeURIComponent(version)}`),

  approveGovernedComponent: (
    componentId: string,
    version: string,
    payload: { validation_run_id: string; validation_digest: string; rationale: string }
  ): Promise<GovernedComponent> =>
    request<GovernedComponent>(`/api/enterprise/v1/governance/components/${encodeURIComponent(componentId)}/${encodeURIComponent(version)}/approve`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  recordValidationRun: (payload: {
    component_id: string;
    component_version: string;
    dataset_digest: string;
    configuration_digest: string;
    metrics: Array<{ name: string; value: number; threshold?: number | null; direction?: string; result: string }>;
    evaluator: string;
    limitations?: string[];
  }): Promise<ValidationRun> =>
    request<ValidationRun>("/api/enterprise/v1/governance/validation-runs", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  listValidationRuns: (componentId?: string): Promise<ValidationRun[]> => {
    const qs = componentId ? `?component_id=${encodeURIComponent(componentId)}` : "";
    return request<ValidationRun[]>(`/api/enterprise/v1/governance/validation-runs${qs}`);
  },

  createRelease: (payload: {
    version: string;
    environment?: string;
    components?: Record<string, string>;
    validation_runs?: string[];
    approval_records?: string[];
    readiness_gates?: Array<Record<string, unknown>>;
  }): Promise<ProductionRelease> =>
    request<ProductionRelease>("/api/enterprise/v1/governance/releases", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  listReleases: (): Promise<ProductionRelease[]> =>
    request<ProductionRelease[]>("/api/enterprise/v1/governance/releases"),

  promoteRelease: (releaseId: string, targetEnvironment: string): Promise<ProductionRelease> =>
    request<ProductionRelease>(`/api/enterprise/v1/governance/releases/${encodeURIComponent(releaseId)}/promote`, {
      method: "POST",
      body: JSON.stringify({ target_environment: targetEnvironment }),
    }),

  rollbackRelease: (releaseId: string, targetReleaseId: string, reason: string): Promise<ProductionRelease> =>
    request<ProductionRelease>(`/api/enterprise/v1/governance/releases/${encodeURIComponent(releaseId)}/rollback`, {
      method: "POST",
      body: JSON.stringify({ target_release_id: targetReleaseId, reason }),
    }),

  suspendComponent: (payload: {
    component_id: string;
    version: string;
    reason: string;
    incident_id?: string;
  }): Promise<SuspensionRecord> =>
    request<SuspensionRecord>("/api/enterprise/v1/governance/kill-switch/suspend", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  resumeComponent: (payload: {
    component_id: string;
    version: string;
    reason: string;
  }): Promise<SuspensionRecord> =>
    request<SuspensionRecord>("/api/enterprise/v1/governance/kill-switch/resume", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  listSuspensions: (activeOnly?: boolean): Promise<SuspensionRecord[]> => {
    const qs = activeOnly ? "?active_only=true" : "";
    return request<SuspensionRecord[]>(`/api/enterprise/v1/governance/kill-switch/suspensions${qs}`);
  },

  createGovernanceIncident: (payload: {
    title: string;
    category: string;
    severity: string;
    affected_components: string[];
    affected_case_ids?: string[];
    detection_source?: string;
    owner?: string;
  }): Promise<GovernanceIncident> =>
    request<GovernanceIncident>("/api/enterprise/v1/governance/incidents", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  updateIncidentStatus: (
    incidentId: string,
    payload: { status: string; remediation_notes?: string; post_incident_review?: string }
  ): Promise<GovernanceIncident> =>
    request<GovernanceIncident>(`/api/enterprise/v1/governance/incidents/${encodeURIComponent(incidentId)}/status`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),

  listGovernanceIncidents: (status?: string): Promise<GovernanceIncident[]> => {
    const qs = status ? `?status=${encodeURIComponent(status)}` : "";
    return request<GovernanceIncident[]>(`/api/enterprise/v1/governance/incidents${qs}`);
  },

  recordDrift: (payload: {
    drift_type: string;
    component_id: string;
    metric_name: string;
    baseline_value: number;
    observed_value: number;
    threshold: number;
    recommended_response?: string;
    details?: Record<string, unknown>;
  }): Promise<DriftRecord> =>
    request<DriftRecord>("/api/enterprise/v1/governance/drift", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  listDriftRecords: (driftType?: string): Promise<DriftRecord[]> => {
    const qs = driftType ? `?drift_type=${encodeURIComponent(driftType)}` : "";
    return request<DriftRecord[]>(`/api/enterprise/v1/governance/drift${qs}`);
  },

  getSystemHealthOverview: (): Promise<SystemHealthOverview> =>
    request<SystemHealthOverview>("/api/enterprise/v1/governance/health"),

  generateEvidencePassport: (findingId: string, caseId: string): Promise<EvidencePassport> =>
    request<EvidencePassport>("/api/enterprise/v1/governance/passports", {
      method: "POST",
      body: JSON.stringify({ finding_id: findingId, case_id: caseId }),
    }),

  getEvidencePassport: (passportId: string): Promise<EvidencePassport> =>
    request<EvidencePassport>(`/api/enterprise/v1/governance/passports/${encodeURIComponent(passportId)}`),

  listEvidencePassports: (caseId?: string): Promise<EvidencePassport[]> => {
    const qs = caseId ? `?case_id=${encodeURIComponent(caseId)}` : "";
    return request<EvidencePassport[]>(`/api/enterprise/v1/governance/passports${qs}`);
  },

  registerAIProvider: (payload: {
    provider_name: string;
    model_identifier: string;
    model_version: string;
    hosting_location: string;
    data_retention_policy: string;
    training_on_customer_data_permitted?: boolean;
    risk_tier?: string;
  }): Promise<GovernedAIProvider> =>
    request<GovernedAIProvider>("/api/enterprise/v1/governance/ai-providers", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  listAIProviders: (): Promise<GovernedAIProvider[]> =>
    request<GovernedAIProvider[]>("/api/enterprise/v1/governance/ai-providers"),

  evaluateReadinessGates: (payload: {
    release_version: string;
    gates: Array<{
      gate_name: string;
      status: string;
      verified_by: string;
      rationale: string;
      evidence_reference?: string;
    }>;
  }): Promise<ReadinessAssessment> =>
    request<ReadinessAssessment>("/api/enterprise/v1/governance/readiness/evaluate", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  getValidationPackage: (releaseVersion: string): Promise<ValidationPackage> =>
    request<ValidationPackage>(`/api/enterprise/v1/governance/readiness/validation-package/${encodeURIComponent(releaseVersion)}`),

  // Phase 13: PKI Digital Signatures & Quantitative Model Risk
  signPassport: (passportId: string, algorithm = "Ed25519"): Promise<EvidencePassport> =>
    request<EvidencePassport>(`/api/enterprise/v1/governance/passports/${encodeURIComponent(passportId)}/sign`, {
      method: "POST",
      body: JSON.stringify({ algorithm }),
    }),

  verifyPassport: (passportId: string, trustedPublicKeyPem?: string): Promise<{ is_valid: boolean; digest_verified: boolean; is_digitally_signed: boolean; signature_verified: boolean; error?: string }> =>
    request(`/api/enterprise/v1/governance/passports/${encodeURIComponent(passportId)}/verify`, {
      method: "POST",
      body: JSON.stringify({ trusted_public_key_pem: trustedPublicKeyPem }),
    }),

  signRelease: (releaseId: string, algorithm = "Ed25519"): Promise<ProductionRelease> =>
    request<ProductionRelease>(`/api/enterprise/v1/governance/releases/${encodeURIComponent(releaseId)}/sign`, {
      method: "POST",
      body: JSON.stringify({ algorithm }),
    }),

  verifyRelease: (releaseId: string, trustedPublicKeyPem?: string): Promise<{ is_valid: boolean; digest_verified: boolean; is_digitally_signed: boolean; signature_verified: boolean; error?: string }> =>
    request(`/api/enterprise/v1/governance/releases/${encodeURIComponent(releaseId)}/verify`, {
      method: "POST",
      body: JSON.stringify({ trusted_public_key_pem: trustedPublicKeyPem }),
    }),

  listQuantitativeDriftEvaluations: (componentId?: string): Promise<QuantitativeDriftEvaluation[]> => {
    const qs = componentId ? `?component_id=${encodeURIComponent(componentId)}` : "";
    return request<QuantitativeDriftEvaluation[]>(`/api/enterprise/v1/governance/model-risk/drift-evaluations${qs}`);
  },

  evaluateQuantitativeDrift: (payload: {
    component_id: string;
    component_version: string;
    baseline_scores: number[];
    current_scores: number[];
    subgroup_predictions?: Record<string, boolean[]>;
  }): Promise<QuantitativeDriftEvaluation> =>
    request<QuantitativeDriftEvaluation>("/api/enterprise/v1/governance/model-risk/drift-evaluations", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  listChampionChallengerRuns: (componentId?: string): Promise<ChampionChallengerRun[]> => {
    const qs = componentId ? `?component_id=${encodeURIComponent(componentId)}` : "";
    return request<ChampionChallengerRun[]>(`/api/enterprise/v1/governance/model-risk/champion-challenger${qs}`);
  },

  evaluateChampionChallenger: (payload: {
    component_id: string;
    champion_version: string;
    challenger_version: string;
    champion_metrics: Record<string, unknown>;
    challenger_metrics: Record<string, unknown>;
    min_sample_size?: number;
    max_fdr_increase?: number;
    min_f1_retention?: number;
    max_p95_latency_ms?: number;
    subgroup_predictions?: Record<string, boolean[]>;
  }): Promise<ChampionChallengerRun> =>
    request<ChampionChallengerRun>("/api/enterprise/v1/governance/model-risk/champion-challenger", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  createForensicDossier: (payload: {
    case_id: string;
    title: string;
    incident_type?: string;
    fraud_loss_amount?: number;
    currency?: string;
    case_summary: string;
    attack_path_summary?: Record<string, unknown>;
    identified_mule_nodes?: Array<Record<string, unknown>>;
    evidence_records?: Array<Record<string, unknown>>;
    certifier_name?: string;
    certifier_designation?: string;
    declaration_text?: string;
  }): Promise<ForensicDossier> =>
    request<ForensicDossier>("/api/enterprise/v1/governance/forensic-dossiers", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  getForensicDossier: (dossierId: string): Promise<ForensicDossier> =>
    request<ForensicDossier>(`/api/enterprise/v1/governance/forensic-dossiers/${encodeURIComponent(dossierId)}`),

  signForensicDossier: (dossierId: string, algorithm = "Ed25519"): Promise<ForensicDossier> =>
    request<ForensicDossier>(`/api/enterprise/v1/governance/forensic-dossiers/${encodeURIComponent(dossierId)}/sign`, {
      method: "POST",
      body: JSON.stringify({ algorithm }),
    }),

  verifyForensicDossier: (dossierId: string, trustedPublicKeyPem?: string): Promise<{ is_valid: boolean; digest_verified: boolean; is_digitally_signed: boolean; signature_verified: boolean; error?: string }> =>
    request(`/api/enterprise/v1/governance/forensic-dossiers/${encodeURIComponent(dossierId)}/verify`, {
      method: "POST",
      body: JSON.stringify({ trusted_public_key_pem: trustedPublicKeyPem }),
    }),

  evaluateInflightPayment: (payload: {
    end_to_end_id: string;
    amount: number;
    currency?: string;
    clearing_rail?: string;
    debtor_name: string;
    debtor_account: string;
    debtor_bic?: string;
    creditor_name: string;
    creditor_account: string;
    creditor_bic?: string;
    remittance_narrative?: string;
    account_prior_transfers_count?: number;
    cop_status?: string | null;
    cop_match_score?: number | null;
    beneficiary_inflow_restriction?: boolean;
    debtor_channel_anomaly?: boolean;
    enable_graduated_controls?: boolean;
    telecom_call_status?: string | null;
    telecom_coercion_score?: number | null;
    check_federated_mule_directory?: boolean;
    use_parallel_pipeline?: boolean;
    sla_budget_ms?: number;
    simulated_latencies?: Record<string, number>;
  }): Promise<InflightPaymentEvaluation> =>
    request<InflightPaymentEvaluation>("/api/enterprise/v1/governance/integrations/iso20022/evaluate-inflight", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  verifyConfirmationOfPayee: (payload: {
    intended_name: string;
    registered_name: string;
    account_number: string;
    account_type?: "PERSONAL" | "BUSINESS";
    clearing_rail?: string;
    bank_bic?: string;
  }): Promise<CopVerifyResponse> =>
    request<CopVerifyResponse>("/api/enterprise/v1/governance/integrations/cop/verify", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  evaluateTelecomSignal: (payload: {
    msisdn: string;
    carrier?: "SAFARICOM" | "AIRTEL" | "TELKOM" | "UNKNOWN";
    query_id?: string;
    simulated_call_status?: "IDLE" | "CALL_IN_PROGRESS" | "RECENT_CALL" | "UNKNOWN";
    simulated_call_duration_seconds?: number;
    simulated_sim_swap_age_hours?: number;
  }): Promise<TelecomSignalResponse> =>
    request<TelecomSignalResponse>("/api/enterprise/v1/governance/integrations/telecom/scam-signal", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  registerFederatedMule: (payload: {
    entity_type: string;
    value: string;
    severity_tier?: string;
    originating_bank_bic?: string;
    reason_code?: string;
    dossier_reference?: string;
    ttl_days?: number;
  }): Promise<FederatedMuleEntry> =>
    request<FederatedMuleEntry>("/api/enterprise/v1/governance/integrations/federated-mules/register", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  queryFederatedMule: (payload: {
    entity_type: string;
    value: string;
    is_already_blinded?: boolean;
  }): Promise<QueryFederatedMuleResponse> =>
    request<QueryFederatedMuleResponse>("/api/enterprise/v1/governance/integrations/federated-mules/query", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  listFederatedMules: (params?: { entity_type?: string; status?: string }): Promise<FederatedMuleEntry[]> => {
    const qs = new URLSearchParams();
    if (params?.entity_type) qs.append("entity_type", params.entity_type);
    if (params?.status) qs.append("status", params.status);
    const q = qs.toString() ? `?${qs.toString()}` : "";
    return request<FederatedMuleEntry[]>(`/api/enterprise/v1/governance/integrations/federated-mules/entries${q}`);
  },

  updateFederatedMuleStatus: (entryId: string, payload: { status: string; justification: string }): Promise<FederatedMuleEntry> =>
    request<FederatedMuleEntry>(`/api/enterprise/v1/governance/integrations/federated-mules/entries/${encodeURIComponent(entryId)}/status`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),

  triggerMuleCascadeTrace: (payload: TriggerMuleCascadeTracePayload): Promise<MuleCascadeTrace> =>
    request<MuleCascadeTrace>("/api/enterprise/v1/governance/intelligence/mule-cascade/trace", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  listMuleCascadeTraces: (): Promise<MuleCascadeTrace[]> =>
    request<MuleCascadeTrace[]>("/api/enterprise/v1/governance/intelligence/mule-cascade/traces"),

  getMuleCascadeTrace: (traceId: string): Promise<MuleCascadeTrace> =>
    request<MuleCascadeTrace>(`/api/enterprise/v1/governance/intelligence/mule-cascade/traces/${encodeURIComponent(traceId)}`),

  executeCascadeDirective: (
    traceId: string,
    payload: ExecuteCascadeDirectivePayload
  ): Promise<ExecuteCascadeDirectiveResponse> =>
    request<ExecuteCascadeDirectiveResponse>(
      `/api/enterprise/v1/governance/intelligence/mule-cascade/traces/${encodeURIComponent(traceId)}/directives/${encodeURIComponent(payload.directive_id)}/execute`,
      {
        method: "POST",
        body: JSON.stringify(payload),
      }
    ),
};
