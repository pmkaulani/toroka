import React, { useEffect, useState } from "react";
import { api } from "../api";
import {
  CaseFingerprint,
  CaseSimilarity,
  CaseSummary,
  InstitutionalPattern,
  MemoryOverview,
  PatternEvaluation,
  PatternMatch,
  Persona,
} from "../types";

interface Props {
  currentPersona: Persona;
}

export const InstitutionalIntelligenceView: React.FC<Props> = ({ currentPersona }) => {
  const [subTab, setSubTab] = useState<"overview" | "library" | "discovery" | "matching" | "governance">("overview");

  // Global State
  const [overview, setOverview] = useState<MemoryOverview | null>(null);
  const [patterns, setPatterns] = useState<InstitutionalPattern[]>([]);
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  // Library & Governance Filter / Selection
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [selectedPattern, setSelectedPattern] = useState<InstitutionalPattern | null>(null);
  const [evaluation, setEvaluation] = useState<PatternEvaluation | null>(null);
  const [evaluating, setEvaluating] = useState<boolean>(false);

  // Governance Form
  const [reviewAction, setReviewAction] = useState<string>("validate");
  const [reviewRationale, setReviewRationale] = useState<string>("");
  const [submittingReview, setSubmittingReview] = useState<boolean>(false);

  // Discovery Form
  const [customPatId, setCustomPatId] = useState<string>("");
  const [customTitle, setCustomTitle] = useState<string>("");
  const [customDesc, setCustomDesc] = useState<string>("");
  const [discovering, setDiscovering] = useState<boolean>(false);

  // Case Matching State
  const [selectedCaseId, setSelectedCaseId] = useState<string>("");
  const [fingerprint, setFingerprint] = useState<CaseFingerprint | null>(null);
  const [similarCases, setSimilarCases] = useState<CaseSimilarity[]>([]);
  const [patternMatches, setPatternMatches] = useState<PatternMatch[]>([]);
  const [matchingLoading, setMatchingLoading] = useState<boolean>(false);

  useEffect(() => {
    loadBaseData();
  }, []);

  const loadBaseData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [ovData, patData, caseResp] = await Promise.all([
        api.getMemoryOverview(),
        api.listPatterns(),
        api.listCases(),
      ]);
      setOverview(ovData);
      setPatterns(patData);
      const caseItems: CaseSummary[] = Array.isArray(caseResp) ? caseResp : (caseResp as any).items || [];
      setCases(caseItems);
      if (caseItems.length > 0 && !selectedCaseId) {
        setSelectedCaseId(caseItems[0].id);
      }
    } catch (err: any) {
      setError(err?.message || "Failed to load institutional intelligence data.");
    } finally {
      setLoading(false);
    }
  };

  const handleDiscoverPatterns = async () => {
    setDiscovering(true);
    setActionMessage(null);
    try {
      const discovered = await api.discoverPatterns(2);
      setActionMessage(`Pattern discovery executed. Discovered ${discovered.length} candidate pattern(s).`);
      await loadBaseData();
    } catch (err: any) {
      setError(err?.message || "Pattern discovery failed.");
    } finally {
      setDiscovering(false);
    }
  };

  const handleSelectPatternForEvaluation = async (pat: InstitutionalPattern) => {
    setSelectedPattern(pat);
    setEvaluating(true);
    try {
      const evalRes = await api.evaluatePattern(pat.pattern_id);
      setEvaluation(evalRes);
    } catch (err: any) {
      setError(err?.message || "Failed to evaluate pattern validation thresholds.");
    } finally {
      setEvaluating(false);
    }
  };

  const handleReviewSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedPattern || !reviewRationale) return;
    setSubmittingReview(true);
    setError(null);
    try {
      const updated = await api.reviewPattern(selectedPattern.pattern_id, {
        action: reviewAction,
        rationale: reviewRationale,
      });
      setActionMessage(`Pattern '${updated.pattern_id}' review submitted successfully: status is now ${updated.status}.`);
      setReviewRationale("");
      await loadBaseData();
      setSelectedPattern(updated);
      handleSelectPatternForEvaluation(updated);
    } catch (err: any) {
      setError(err?.message || "Review action failed.");
    } finally {
      setSubmittingReview(false);
    }
  };

  const handleExecuteCaseMatching = async (caseId: string) => {
    if (!caseId) return;
    setMatchingLoading(true);
    setError(null);
    try {
      const [fp, sims, pats] = await Promise.all([
        api.getCaseFingerprint(caseId),
        api.getSimilarHistoricalCases(caseId, 5, 0.1),
        api.matchCasePatterns(caseId, 0.1),
      ]);
      setFingerprint(fp);
      setSimilarCases(sims);
      setPatternMatches(pats);
    } catch (err: any) {
      setError(err?.message || "Failed to execute case matching.");
    } finally {
      setMatchingLoading(false);
    }
  };

  const handleCreateCustomPattern = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!customPatId || !customTitle || !customDesc) return;
    setError(null);
    try {
      const created = await api.createCandidatePattern({
        pattern_id: customPatId,
        title: customTitle,
        description: customDesc,
        feature_signature: {
          "sensitive_change.beneficiary": "present",
          "sequence.customer_record_access_to_beneficiary_change": "present",
        },
        independent_source_systems: ["core_banking", "crm_support"],
        control_weaknesses: ["customer_authorisation_evidence_gap"],
      });
      setActionMessage(`Custom candidate pattern '${created.pattern_id}' registered.`);
      setCustomPatId("");
      setCustomTitle("");
      setCustomDesc("");
      await loadBaseData();
    } catch (err: any) {
      setError(err?.message || "Failed to create candidate pattern.");
    }
  };

  return (
    <div className="wb-content-inner" style={{ padding: "1.5rem" }}>
      {/* View Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "1.5rem" }}>
        <div>
          <h2 style={{ margin: 0, fontSize: "1.5rem", fontWeight: 700, color: "var(--color-primary-text)" }}>
            Institutional Intelligence & Fraud DNA
          </h2>
          <p style={{ margin: "0.25rem 0 0", color: "var(--color-secondary-text)", fontSize: "0.9rem" }}>
            Deterministic institutional memory, recurring fraud typologies, control weakness tracking, and explainable case similarity.
          </p>
        </div>
        <div style={{ display: "flex", gap: "0.75rem" }}>
          <button
            className="wb-button wb-button-primary"
            onClick={handleDiscoverPatterns}
            disabled={discovering}
          >
            {discovering ? "Discovering..." : "⚡ Mine Candidate Patterns"}
          </button>
        </div>
      </div>

      {/* Notifications */}
      {actionMessage && (
        <div className="wb-banner" style={{ backgroundColor: "#e6f4ea", color: "#137333", border: "1px solid #ceead6", padding: "0.75rem 1rem", borderRadius: "4px", marginBottom: "1rem" }}>
          ✓ {actionMessage}
        </div>
      )}
      {error && (
        <div className="wb-banner" style={{ backgroundColor: "#fce8e6", color: "#c5221f", border: "1px solid #fad2cf", padding: "0.75rem 1rem", borderRadius: "4px", marginBottom: "1rem" }}>
          ⚠ {error}
        </div>
      )}

      {/* Sub-navigation tabs */}
      <div style={{ display: "flex", gap: "0.5rem", borderBottom: "1px solid var(--color-border)", marginBottom: "1.5rem" }}>
        <button
          className={`wb-tab ${subTab === "overview" ? "active" : ""}`}
          onClick={() => setSubTab("overview")}
        >
          Memory Overview
        </button>
        <button
          className={`wb-tab ${subTab === "library" ? "active" : ""}`}
          onClick={() => setSubTab("library")}
        >
          Pattern Library ({patterns.length})
        </button>
        <button
          className={`wb-tab ${subTab === "discovery" ? "active" : ""}`}
          onClick={() => setSubTab("discovery")}
        >
          Typology Discovery
        </button>
        <button
          className={`wb-tab ${subTab === "matching" ? "active" : ""}`}
          onClick={() => {
            setSubTab("matching");
            if (selectedCaseId && !fingerprint) {
              handleExecuteCaseMatching(selectedCaseId);
            }
          }}
        >
          Case Matching & Fingerprints
        </button>
        <button
          className={`wb-tab ${subTab === "governance" ? "active" : ""}`}
          onClick={() => setSubTab("governance")}
        >
          Governance & Dual-Control
        </button>
      </div>

      {loading && <p>Loading institutional memory telemetry...</p>}

      {/* 1. MEMORY OVERVIEW */}
      {!loading && subTab === "overview" && overview && (
        <div>
          {/* Top KPI Cards */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "1rem", marginBottom: "1.5rem" }}>
            <div className="wb-card" style={{ padding: "1rem" }}>
              <div style={{ fontSize: "0.8rem", color: "var(--color-secondary-text)" }}>Adjudicated Cases</div>
              <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "#1a73e8" }}>{overview.adjudicated_case_count}</div>
              <div style={{ fontSize: "0.75rem", color: "#5f6368" }}>Independently labeled</div>
            </div>
            <div className="wb-card" style={{ padding: "1rem" }}>
              <div style={{ fontSize: "0.8rem", color: "var(--color-secondary-text)" }}>Validated Patterns</div>
              <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "#137333" }}>{overview.validated_pattern_count}</div>
              <div style={{ fontSize: "0.75rem", color: "#5f6368" }}>Dual-control approved</div>
            </div>
            <div className="wb-card" style={{ padding: "1rem" }}>
              <div style={{ fontSize: "0.8rem", color: "var(--color-secondary-text)" }}>Candidate Patterns</div>
              <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "#ea8600" }}>{overview.candidate_pattern_count}</div>
              <div style={{ fontSize: "0.75rem", color: "#5f6368" }}>Pending validation review</div>
            </div>
            <div className="wb-card" style={{ padding: "1rem" }}>
              <div style={{ fontSize: "0.8rem", color: "var(--color-secondary-text)" }}>Suspended / Retired</div>
              <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "#d93025" }}>
                {overview.suspended_pattern_count + overview.retired_pattern_count}
              </div>
              <div style={{ fontSize: "0.75rem", color: "#5f6368" }}>Inactive or superseded</div>
            </div>
            <div className="wb-card" style={{ padding: "1rem" }}>
              <div style={{ fontSize: "0.8rem", color: "var(--color-secondary-text)" }}>Avg Telemetry Coverage</div>
              <div style={{ fontSize: "1.75rem", fontWeight: 700, color: "#188038" }}>
                {(overview.average_source_coverage * 100).toFixed(1)}%
              </div>
              <div style={{ fontSize: "0.75rem", color: "#5f6368" }}>Across {overview.total_fingerprinted_cases} fingerprinted cases</div>
            </div>
          </div>

          {/* Institutional Memory Architecture Summary */}
          <div className="wb-card" style={{ padding: "1.25rem", marginBottom: "1.5rem" }}>
            <h3 style={{ margin: "0 0 0.5rem", fontSize: "1.1rem" }}>Institutional Memory Lifecycle</h3>
            <p style={{ color: "var(--color-secondary-text)", fontSize: "0.85rem", margin: "0 0 1rem" }}>
              Closed investigations undergo Phase 8 independent ground truth adjudication. Deterministic extraction transforms confirmed cases into zero-PII fingerprints. Recurring sequences and control weaknesses form candidates, which undergo dual-control validation review before becoming official institutional memory.
            </p>
            <div style={{ display: "flex", gap: "1rem", flexWrap: "wrap" }}>
              <div style={{ flex: 1, minWidth: "220px", padding: "0.75rem", backgroundColor: "rgba(0,0,0,0.02)", borderRadius: "4px" }}>
                <strong>1. Closed Investigation</strong>
                <p style={{ fontSize: "0.8rem", margin: "0.25rem 0 0" }}>Adjudicated as confirmed fraud or legitimate through dual control.</p>
              </div>
              <div style={{ flex: 1, minWidth: "220px", padding: "0.75rem", backgroundColor: "rgba(0,0,0,0.02)", borderRadius: "4px" }}>
                <strong>2. Zero-PII Fingerprint</strong>
                <p style={{ fontSize: "0.8rem", margin: "0.25rem 0 0" }}>Dimensions, sequences, and control weaknesses without identities.</p>
              </div>
              <div style={{ flex: 1, minWidth: "220px", padding: "0.75rem", backgroundColor: "rgba(0,0,0,0.02)", borderRadius: "4px" }}>
                <strong>3. Candidate Typology</strong>
                <p style={{ fontSize: "0.8rem", margin: "0.25rem 0 0" }}>Multi-case clustering with confirmed legitimate counterexamples.</p>
              </div>
              <div style={{ flex: 1, minWidth: "220px", padding: "0.75rem", backgroundColor: "rgba(0,0,0,0.02)", borderRadius: "4px" }}>
                <strong>4. Governed Intelligence</strong>
                <p style={{ fontSize: "0.8rem", margin: "0.25rem 0 0" }}>Independent authoriser approval with strict audit hash chaining.</p>
              </div>
            </div>
          </div>

          {/* Recent Reviews Audit */}
          <div className="wb-card" style={{ padding: "1.25rem" }}>
            <h3 style={{ margin: "0 0 1rem", fontSize: "1.1rem" }}>Recent Pattern Reviews</h3>
            {overview.recent_reviews.length === 0 ? (
              <p style={{ color: "var(--color-secondary-text)", fontSize: "0.85rem" }}>No pattern reviews recorded yet.</p>
            ) : (
              <table className="wb-table" style={{ width: "100%", fontSize: "0.85rem" }}>
                <thead>
                  <tr>
                    <th>Review ID</th>
                    <th>Pattern ID</th>
                    <th>Version</th>
                    <th>Action</th>
                    <th>Reviewer</th>
                    <th>Rationale</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {overview.recent_reviews.map((r) => (
                    <tr key={r.review_id}>
                      <td style={{ fontFamily: "monospace" }}>{r.review_id.slice(0, 8)}</td>
                      <td><strong>{r.pattern_id}</strong></td>
                      <td>v{r.pattern_version}</td>
                      <td>
                        <span className={`wb-badge wb-badge-${r.action === "validate" ? "success" : r.action === "reject" ? "danger" : "warning"}`}>
                          {r.action}
                        </span>
                      </td>
                      <td>{r.reviewer_subject}</td>
                      <td>{r.rationale}</td>
                      <td>{new Date(r.created_at).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* 2. PATTERN LIBRARY */}
      {!loading && subTab === "library" && (
        <div>
          <div style={{ display: "flex", gap: "1rem", alignItems: "center", marginBottom: "1rem" }}>
            <label style={{ fontSize: "0.85rem", fontWeight: 600 }}>Filter by Status:</label>
            <select
              className="wb-input"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              style={{ width: "200px" }}
            >
              <option value="">All Statuses</option>
              <option value="validated">Validated</option>
              <option value="candidate">Candidate</option>
              <option value="under_review">Under Review</option>
              <option value="suspended">Suspended</option>
              <option value="retired">Retired</option>
            </select>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(360px, 1fr))", gap: "1rem" }}>
            {patterns
              .filter((p) => !statusFilter || p.status === statusFilter)
              .map((pat) => (
                <div key={pat.pattern_id} className="wb-card" style={{ padding: "1.25rem", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "0.5rem" }}>
                      <span style={{ fontFamily: "monospace", fontSize: "0.8rem", color: "var(--color-secondary-text)" }}>
                        {pat.pattern_id} (v{pat.version})
                      </span>
                      <span
                        className={`wb-badge wb-badge-${
                          pat.status === "validated" ? "success" : pat.status === "candidate" ? "warning" : pat.status === "suspended" ? "danger" : "default"
                        }`}
                      >
                        {pat.status.toUpperCase()}
                      </span>
                    </div>
                    <h4 style={{ margin: "0 0 0.5rem", fontSize: "1rem" }}>{pat.title}</h4>
                    <p style={{ fontSize: "0.85rem", color: "var(--color-secondary-text)", margin: "0 0 1rem" }}>
                      {pat.description}
                    </p>

                    <div style={{ fontSize: "0.8rem", marginBottom: "0.5rem" }}>
                      <strong>Contributing Cases:</strong> {pat.confirmed_fraud_case_ids.length} fraud, {pat.confirmed_legitimate_case_ids.length} legitimate comparison(s)
                    </div>

                    <div style={{ fontSize: "0.8rem", marginBottom: "0.5rem" }}>
                      <strong>Sources:</strong> {pat.independent_source_systems.join(", ") || "None recorded"}
                    </div>

                    {pat.control_weaknesses.length > 0 && (
                      <div style={{ fontSize: "0.8rem", marginBottom: "0.75rem" }}>
                        <strong>Control Weaknesses:</strong>
                        <div style={{ display: "flex", gap: "0.25rem", flexWrap: "wrap", marginTop: "0.25rem" }}>
                          {pat.control_weaknesses.map((cw) => (
                            <span key={cw} style={{ fontSize: "0.7rem", backgroundColor: "#fef7e0", color: "#b06000", padding: "2px 6px", borderRadius: "3px" }}>
                              {cw}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  <div style={{ borderTop: "1px solid var(--color-border)", paddingTop: "0.75rem", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ fontSize: "0.75rem", color: "var(--color-secondary-text)" }}>
                      Curated by: {pat.curator_subject}
                    </span>
                    <button
                      className="wb-button wb-button-secondary"
                      style={{ fontSize: "0.8rem", padding: "0.3rem 0.6rem" }}
                      onClick={() => {
                        handleSelectPatternForEvaluation(pat);
                        setSubTab("governance");
                      }}
                    >
                      Governance Review →
                    </button>
                  </div>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* 3. PATTERN DISCOVERY */}
      {!loading && subTab === "discovery" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem" }}>
          {/* Mining Controls */}
          <div className="wb-card" style={{ padding: "1.25rem" }}>
            <h3 style={{ margin: "0 0 0.5rem", fontSize: "1.1rem" }}>Automated Typology Mining</h3>
            <p style={{ color: "var(--color-secondary-text)", fontSize: "0.85rem", margin: "0 0 1rem" }}>
              Analyzes all fingerprinted cases with Phase 8 confirmed outcomes. Discovers recurring temporal sequences, control circumvention vectors, and cross-system anomalies.
            </p>
            <div style={{ marginBottom: "1rem" }}>
              <button
                className="wb-button wb-button-primary"
                onClick={handleDiscoverPatterns}
                disabled={discovering}
              >
                {discovering ? "Mining Adjudicated Cases..." : "⚡ Run Deterministic Mining Engine"}
              </button>
            </div>

            <h4 style={{ margin: "1.5rem 0 0.5rem", fontSize: "0.95rem" }}>Discovery Principles</h4>
            <ul style={{ fontSize: "0.85rem", color: "var(--color-secondary-text)", paddingLeft: "1.2rem", margin: 0 }}>
              <li><strong>Multi-case support:</strong> A pattern requires at least 2 independent confirmed fraud investigations.</li>
              <li><strong>Legitimate counterexamples:</strong> Legitimate cases with similar sequences are captured as controls.</li>
              <li><strong>Zero-PII guarantee:</strong> Patterns retain behavioral dimensions, not employee or customer IDs.</li>
              <li><strong>Preserves Unknowns:</strong> Gaps in source telemetry are treated as incomplete, not negative evidence.</li>
            </ul>
          </div>

          {/* Custom Candidate Proposal Form */}
          <div className="wb-card" style={{ padding: "1.25rem" }}>
            <h3 style={{ margin: "0 0 0.5rem", fontSize: "1.1rem" }}>Curate Candidate Typology</h3>
            <p style={{ color: "var(--color-secondary-text)", fontSize: "0.85rem", margin: "0 0 1rem" }}>
              Investigative staff can formalize observed typologies for institutional evaluation.
            </p>
            <form onSubmit={handleCreateCustomPattern}>
              <div style={{ marginBottom: "0.75rem" }}>
                <label style={{ display: "block", fontSize: "0.8rem", fontWeight: 600, marginBottom: "0.25rem" }}>
                  Pattern Identifier:
                </label>
                <input
                  type="text"
                  className="wb-input"
                  style={{ width: "100%" }}
                  placeholder="e.g. PAT-PAYROLL-001"
                  value={customPatId}
                  onChange={(e) => setCustomPatId(e.target.value)}
                  required
                />
              </div>
              <div style={{ marginBottom: "0.75rem" }}>
                <label style={{ display: "block", fontSize: "0.8rem", fontWeight: 600, marginBottom: "0.25rem" }}>
                  Title:
                </label>
                <input
                  type="text"
                  className="wb-input"
                  style={{ width: "100%" }}
                  placeholder="e.g. Payroll Beneficiary Manipulation Typology"
                  value={customTitle}
                  onChange={(e) => setCustomTitle(e.target.value)}
                  required
                />
              </div>
              <div style={{ marginBottom: "0.75rem" }}>
                <label style={{ display: "block", fontSize: "0.8rem", fontWeight: 600, marginBottom: "0.25rem" }}>
                  Description:
                </label>
                <textarea
                  className="wb-input"
                  style={{ width: "100%", height: "80px" }}
                  placeholder="Detailed behavioral pattern and operational sequence description..."
                  value={customDesc}
                  onChange={(e) => setCustomDesc(e.target.value)}
                  required
                />
              </div>
              <button type="submit" className="wb-button wb-button-secondary">
                Submit Candidate for Review
              </button>
            </form>
          </div>
        </div>
      )}

      {/* 4. CASE MATCHING & FINGERPRINTS */}
      {!loading && subTab === "matching" && (
        <div>
          {/* Case Selector Header */}
          <div className="wb-card" style={{ padding: "1.25rem", marginBottom: "1.5rem", display: "flex", gap: "1rem", alignItems: "center" }}>
            <label style={{ fontSize: "0.9rem", fontWeight: 600 }}>Select Active Investigation:</label>
            <select
              className="wb-input"
              value={selectedCaseId}
              onChange={(e) => {
                setSelectedCaseId(e.target.value);
                handleExecuteCaseMatching(e.target.value);
              }}
              style={{ minWidth: "320px" }}
            >
              {cases.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.label} ({c.id.slice(0, 8)}) - {c.status.toUpperCase()}
                </option>
              ))}
            </select>
            <button
              className="wb-button wb-button-primary"
              onClick={() => handleExecuteCaseMatching(selectedCaseId)}
              disabled={matchingLoading}
            >
              {matchingLoading ? "Matching..." : "🔍 Compare Against Institutional Memory"}
            </button>
          </div>

          {fingerprint && (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: "1.5rem" }}>
              {/* Case Fingerprint Dimensions */}
              <div className="wb-card" style={{ padding: "1.25rem" }}>
                <h3 style={{ margin: "0 0 0.5rem", fontSize: "1.1rem" }}>Zero-PII Behavioral Fingerprint</h3>
                <div style={{ fontSize: "0.8rem", color: "var(--color-secondary-text)", marginBottom: "1rem" }}>
                  Case ID: <code>{fingerprint.case_id}</code> | Version: <code>{fingerprint.extractor_version}</code>
                </div>

                <div style={{ marginBottom: "1rem" }}>
                  <strong>Source Coverage:</strong> {(fingerprint.source_coverage * 100).toFixed(1)}%
                  <div style={{ fontSize: "0.75rem", color: "#5f6368" }}>
                    Sources observed: {fingerprint.source_systems.join(", ") || "None"}
                  </div>
                </div>

                <div style={{ marginBottom: "1rem" }}>
                  <strong>Control Weaknesses Detected:</strong>
                  {fingerprint.control_weaknesses.length === 0 ? (
                    <div style={{ fontSize: "0.8rem", color: "var(--color-secondary-text)" }}>None observed</div>
                  ) : (
                    <ul style={{ margin: "0.25rem 0 0", paddingLeft: "1.2rem", fontSize: "0.8rem" }}>
                      {fingerprint.control_weaknesses.map((cw) => (
                        <li key={cw} style={{ color: "#b06000", fontWeight: 600 }}>{cw}</li>
                      ))}
                    </ul>
                  )}
                </div>

                <div>
                  <strong>Key Feature Dimensions:</strong>
                  <div style={{ maxHeight: "250px", overflowY: "auto", marginTop: "0.5rem", fontSize: "0.75rem" }}>
                    <table className="wb-table" style={{ width: "100%" }}>
                      <thead>
                        <tr>
                          <th>Dimension</th>
                          <th>Value</th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.entries(fingerprint.features).map(([dim, val]) => (
                          <tr key={dim}>
                            <td style={{ fontFamily: "monospace" }}>{dim}</td>
                            <td>
                              <span style={{
                                fontWeight: 600,
                                color: val.startsWith("present") ? "#137333" : val === "absent" ? "#5f6368" : "#ea8600",
                              }}>
                                {val}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>

              {/* Historical Case & Pattern Matching Results */}
              <div>
                {/* 1. Similar Historical Cases */}
                <div className="wb-card" style={{ padding: "1.25rem", marginBottom: "1.5rem" }}>
                  <h3 style={{ margin: "0 0 0.5rem", fontSize: "1.1rem" }}>Similar Historical Investigations</h3>
                  <p style={{ color: "var(--color-secondary-text)", fontSize: "0.85rem", margin: "0 0 1rem" }}>
                    Ranked by deterministic feature similarity. Similarity index is not a calibrated fraud probability; it reflects agreement on observed dimensions.
                  </p>

                  {similarCases.length === 0 ? (
                    <p style={{ color: "var(--color-secondary-text)", fontSize: "0.85rem" }}>
                      No historical cases met the minimum comparison coverage threshold.
                    </p>
                  ) : (
                    <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
                      {similarCases.map((sim) => (
                        <div key={sim.historical_case_id} style={{ border: "1px solid var(--color-border)", borderRadius: "4px", padding: "1rem" }}>
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
                            <div>
                              <strong>Case Ref: {sim.historical_case_id.slice(0, 8)}...</strong>
                              <span style={{ marginLeft: "0.5rem" }} className={`wb-badge wb-badge-${sim.historical_outcome === "confirmed_fraud" ? "danger" : "success"}`}>
                                {sim.historical_outcome || "UNLABELLED"}
                              </span>
                            </div>
                            <div style={{ textAlign: "right" }}>
                              <span style={{ fontSize: "1.1rem", fontWeight: 700, color: "#1a73e8" }}>
                                {sim.similarity_index != null ? `${(sim.similarity_index * 100).toFixed(1)}%` : "N/A"}
                              </span>
                              <div style={{ fontSize: "0.75rem", color: "var(--color-secondary-text)" }}>
                                Coverage: {(sim.comparison_coverage * 100).toFixed(1)}%
                              </div>
                            </div>
                          </div>
                          <p style={{ fontSize: "0.85rem", margin: "0 0 0.5rem" }}>
                            {sim.summary_explanation}
                          </p>
                          <div style={{ fontSize: "0.8rem", color: "var(--color-secondary-text)" }}>
                            <strong>Matched ({sim.matched_features.length}):</strong> {sim.matched_features.slice(0, 3).join(", ")}
                            {sim.different_features.length > 0 && (
                              <span style={{ marginLeft: "0.75rem" }}>
                                <strong>Different ({sim.different_features.length}):</strong> {sim.different_features.slice(0, 2).join(", ")}
                              </span>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* 2. Institutional Pattern Matches */}
                <div className="wb-card" style={{ padding: "1.25rem" }}>
                  <h3 style={{ margin: "0 0 0.5rem", fontSize: "1.1rem" }}>Institutional Pattern Matches</h3>
                  {patternMatches.length === 0 ? (
                    <p style={{ color: "var(--color-secondary-text)", fontSize: "0.85rem" }}>
                      No matching institutional patterns identified for this case telemetry.
                    </p>
                  ) : (
                    <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
                      {patternMatches.map((pm) => (
                        <div key={pm.pattern_id} style={{ border: "1px solid var(--color-border)", borderRadius: "4px", padding: "1rem" }}>
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
                            <div>
                              <strong>{pm.pattern_title}</strong>
                              <span style={{ marginLeft: "0.5rem", fontFamily: "monospace", fontSize: "0.8rem" }}>
                                ({pm.pattern_id} v{pm.pattern_version})
                              </span>
                              <span style={{ marginLeft: "0.5rem" }} className={`wb-badge wb-badge-${pm.pattern_status === "validated" ? "success" : "warning"}`}>
                                {pm.pattern_status}
                              </span>
                            </div>
                            <div style={{ textAlign: "right" }}>
                              <span style={{ fontSize: "1.1rem", fontWeight: 700, color: "#137333" }}>
                                {pm.similarity_index != null ? `${(pm.similarity_index * 100).toFixed(1)}%` : "N/A"}
                              </span>
                              <div style={{ fontSize: "0.75rem", color: "var(--color-secondary-text)" }}>
                                Signature Coverage: {(pm.comparison_coverage * 100).toFixed(1)}%
                              </div>
                            </div>
                          </div>
                          <p style={{ fontSize: "0.85rem", margin: "0 0 0.5rem" }}>
                            {pm.explanation}
                          </p>
                          <div style={{ fontSize: "0.8rem", color: "var(--color-secondary-text)" }}>
                            Contributing Controls: {pm.confirmed_fraud_cases_count} fraud cases, {pm.confirmed_legitimate_cases_count} legitimate comparisons.
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* 5. PATTERN GOVERNANCE */}
      {!loading && subTab === "governance" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem" }}>
          {/* Pattern Selection & Validation Threshold Check */}
          <div className="wb-card" style={{ padding: "1.25rem" }}>
            <h3 style={{ margin: "0 0 0.5rem", fontSize: "1.1rem" }}>Validation Threshold Assessment</h3>
            <p style={{ color: "var(--color-secondary-text)", fontSize: "0.85rem", margin: "0 0 1rem" }}>
              Select a pattern to verify compliance with institutional governance policy.
            </p>

            <div style={{ marginBottom: "1rem" }}>
              <label style={{ display: "block", fontSize: "0.8rem", fontWeight: 600, marginBottom: "0.25rem" }}>
                Select Pattern:
              </label>
              <select
                className="wb-input"
                style={{ width: "100%" }}
                value={selectedPattern?.pattern_id || ""}
                onChange={(e) => {
                  const pat = patterns.find((p) => p.pattern_id === e.target.value);
                  if (pat) handleSelectPatternForEvaluation(pat);
                }}
              >
                <option value="">-- Choose a Pattern --</option>
                {patterns.map((p) => (
                  <option key={p.pattern_id} value={p.pattern_id}>
                    {p.pattern_id} - {p.title} ({p.status})
                  </option>
                ))}
              </select>
            </div>

            {selectedPattern && (
              <div style={{ marginTop: "1rem" }}>
                <div style={{ padding: "0.75rem", backgroundColor: "rgba(0,0,0,0.02)", borderRadius: "4px", marginBottom: "1rem" }}>
                  <strong>{selectedPattern.title}</strong>
                  <div style={{ fontSize: "0.8rem", color: "var(--color-secondary-text)", marginTop: "0.25rem" }}>
                    Status: <span className="wb-badge wb-badge-default">{selectedPattern.status}</span> | Version: v{selectedPattern.version} | Curator: {selectedPattern.curator_subject}
                  </div>
                  <p style={{ fontSize: "0.85rem", margin: "0.5rem 0 0" }}>{selectedPattern.description}</p>
                </div>

                {evaluating && <p style={{ fontSize: "0.85rem" }}>Evaluating policy compliance...</p>}

                {evaluation && (
                  <div>
                    <h4 style={{ margin: "0 0 0.5rem", fontSize: "0.95rem" }}>
                      Policy Status:{" "}
                      <span style={{ color: evaluation.eligible_for_review ? "#137333" : "#c5221f" }}>
                        {evaluation.eligible_for_review ? "✓ Eligible for Validation Review" : "⚠ Policy Blockers Active"}
                      </span>
                    </h4>

                    <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem", marginBottom: "1rem" }}>
                      {Object.entries(evaluation.checks).map(([check, passed]) => (
                        <div key={check} style={{ display: "flex", alignItems: "center", gap: "0.5rem", fontSize: "0.8rem" }}>
                          <span style={{ color: passed ? "#137333" : "#c5221f", fontWeight: 700 }}>
                            {passed ? "✓" : "✗"}
                          </span>
                          <span style={{ fontFamily: "monospace" }}>{check}</span>
                        </div>
                      ))}
                    </div>

                    {evaluation.blockers.length > 0 && (
                      <div style={{ padding: "0.75rem", backgroundColor: "#fce8e6", borderRadius: "4px", fontSize: "0.8rem", color: "#c5221f" }}>
                        <strong>Validation Blockers:</strong>
                        <ul style={{ margin: "0.25rem 0 0", paddingLeft: "1.2rem" }}>
                          {evaluation.blockers.map((b, idx) => (
                            <li key={idx}>{b}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Dual-Control Maker-Checker Action Form */}
          <div className="wb-card" style={{ padding: "1.25rem" }}>
            <h3 style={{ margin: "0 0 0.5rem", fontSize: "1.1rem" }}>Dual-Control Review Action</h3>
            <p style={{ color: "var(--color-secondary-text)", fontSize: "0.85rem", margin: "0 0 1rem" }}>
              Enforces strict maker-checker independence. The curator or creator cannot approve or validate their own pattern.
            </p>

            {selectedPattern && currentPersona.id === selectedPattern.curator_subject && (
              <div style={{ padding: "0.75rem", backgroundColor: "#fef7e0", color: "#b06000", borderRadius: "4px", fontSize: "0.8rem", marginBottom: "1rem" }}>
                ⚠ <strong>Maker-Checker Notice:</strong> You are currently logged in as <code>{currentPersona.id}</code>, who is the curator of this pattern. Under institutional policy, an independent authoriser must submit validation decisions.
              </div>
            )}

            <form onSubmit={handleReviewSubmit}>
              <div style={{ marginBottom: "0.75rem" }}>
                <label style={{ display: "block", fontSize: "0.8rem", fontWeight: 600, marginBottom: "0.25rem" }}>
                  Review Action:
                </label>
                <select
                  className="wb-input"
                  style={{ width: "100%" }}
                  value={reviewAction}
                  onChange={(e) => setReviewAction(e.target.value)}
                  disabled={!selectedPattern}
                >
                  <option value="validate">Validate & Promote to Institutional Memory</option>
                  <option value="submit_for_review">Submit for Review</option>
                  <option value="reject">Reject Candidate</option>
                  <option value="suspend">Suspend Pattern</option>
                  <option value="reinstate">Reinstate Pattern</option>
                  <option value="retire">Permanently Retire</option>
                </select>
              </div>

              <div style={{ marginBottom: "0.75rem" }}>
                <label style={{ display: "block", fontSize: "0.8rem", fontWeight: 600, marginBottom: "0.25rem" }}>
                  Review Rationale & Evidence Audit:
                </label>
                <textarea
                  className="wb-input"
                  style={{ width: "100%", height: "100px" }}
                  placeholder="Document independent evaluation findings, counterexample analysis, and regulatory justification..."
                  value={reviewRationale}
                  onChange={(e) => setReviewRationale(e.target.value)}
                  required
                  disabled={!selectedPattern}
                />
              </div>

              <button
                type="submit"
                className="wb-button wb-button-primary"
                disabled={!selectedPattern || submittingReview || !reviewRationale}
              >
                {submittingReview ? "Submitting Review..." : "Execute Review Decision"}
              </button>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
