import React, { useEffect, useState } from "react";
import { api } from "../api";
import {
  CaseSummary,
  CorrelationSignal,
  InvestigationBundle,
} from "../types";

interface InvestigationViewProps {
  initialCaseId?: string | null;
  onSelectCase?: (caseId: string) => void;
}

export const InvestigationView: React.FC<InvestigationViewProps> = ({
  initialCaseId,
  onSelectCase,
}) => {
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(initialCaseId || null);
  const [bundle, setBundle] = useState<InvestigationBundle | null>(null);
  const [systemSignals, setSystemSignals] = useState<CorrelationSignal[]>([]);
  const [loading, setLoading] = useState(false);
  const [correlating, setCorrelating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeSection, setActiveSection] = useState<
    "overview" | "timeline" | "signals" | "hypotheses" | "evidence" | "relationships"
  >("overview");

  // New Hypothesis Form State
  const [newHypoTitle, setNewHypoTitle] = useState("");
  const [newHypoDesc, setNewHypoDesc] = useState("");
  const [newHypoStatus, setNewHypoStatus] = useState<"open" | "supported" | "weakened" | "disproven">("open");
  const [newHypoConfidence, setNewHypoConfidence] = useState(0.5);
  const [newHypoNote, setNewHypoNote] = useState("");
  const [savingHypo, setSavingHypo] = useState(false);

  // Load cases list & system-wide signals on mount
  useEffect(() => {
    api
      .listCases()
      .then((res) => {
        setCases(res.items);
        if (!selectedCaseId && res.items.length > 0) {
          setSelectedCaseId(res.items[0].id);
        }
      })
      .catch((err) => setError(err.message));

    api
      .listCorrelationSignals(50)
      .then((sigs) => setSystemSignals(sigs))
      .catch(() => {});
  }, []);

  // Load investigation bundle when selected case changes
  useEffect(() => {
    if (!selectedCaseId) return;
    setLoading(true);
    setError(null);
    api
      .getCaseInvestigation(selectedCaseId)
      .then((data) => setBundle(data))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [selectedCaseId]);

  const handleRunCorrelation = async () => {
    if (!selectedCaseId) return;
    setCorrelating(true);
    setError(null);
    try {
      await api.correlateCase(selectedCaseId, { window_before_minutes: 60, window_after_minutes: 60 });
      const refreshed = await api.getCaseInvestigation(selectedCaseId);
      setBundle(refreshed);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setCorrelating(false);
    }
  };

  const handleCreateHypothesis = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCaseId || !newHypoTitle.trim()) return;
    setSavingHypo(true);
    setError(null);
    try {
      const hypoId = `H-${Date.now().toString(36)}`;
      await api.saveCaseHypothesis(selectedCaseId, {
        hypothesis_id: hypoId,
        title: newHypoTitle,
        description: newHypoDesc,
        status: newHypoStatus,
        confidence: Number(newHypoConfidence),
        investigator_note: newHypoNote || undefined,
      });
      // Refresh bundle
      const refreshed = await api.getCaseInvestigation(selectedCaseId);
      setBundle(refreshed);
      setNewHypoTitle("");
      setNewHypoDesc("");
      setNewHypoNote("");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSavingHypo(false);
    }
  };

  const selectedCase = cases.find((c) => c.id === selectedCaseId);

  return (
    <div>
      {/* Top Bar: Case Selector & Action Header */}
      <div className="wb-card">
        <div className="wb-card-header">
          <div>
            <h2 className="wb-card-title">Cross-System Fraud Intelligence &amp; Correlation</h2>
            <p className="wb-card-subtitle">
              {selectedCase ? `${selectedCase.focus} (${selectedCase.label}) • ` : ""}
              Multi-system temporal sequencing &bull; Competing hypothesis testing &bull; Non-accusatory evidence synthesis
              {systemSignals.length > 0 ? ` • ${systemSignals.length} cross-system signals indexed` : ""}
            </p>
          </div>
          <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
            <label style={{ fontSize: 12, color: "var(--text-muted)" }}>Active Case:</label>
            <select
              value={selectedCaseId || ""}
              onChange={(e) => {
                setSelectedCaseId(e.target.value);
                if (onSelectCase) onSelectCase(e.target.value);
              }}
              style={{
                padding: "6px 12px",
                background: "var(--card-bg)",
                color: "var(--text-color)",
                border: "1px solid var(--border-color)",
                borderRadius: 4,
                fontSize: 13,
              }}
            >
              {cases.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.focus} — {c.label} ({c.id.slice(0, 8)})
                </option>
              ))}
            </select>
            <button
              className="wb-btn"
              onClick={handleRunCorrelation}
              disabled={correlating || !selectedCaseId}
            >
              {correlating ? "Correlating Events..." : "Run Temporal Correlation"}
            </button>
          </div>
        </div>

        {error && (
          <div className="notice-banner" style={{ borderColor: "var(--accent-rose)", color: "#fca5a5", marginBottom: 12 }}>
            <strong>Intelligence Engine Notice:</strong> {error}
          </div>
        )}

        {/* Investigation Summary Banner */}
        {bundle && bundle.summary && (
          <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border-color)", padding: 16, borderRadius: 6, marginTop: 12 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 8 }}>
              <div>
                <span style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: 1, color: "var(--accent-blue)", fontWeight: 600 }}>
                  Primary Observed Pattern
                </span>
                <h3 style={{ fontSize: 16, margin: "4px 0", color: "var(--text-color)" }}>
                  {bundle.summary.finding}
                </h3>
              </div>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <span className="chip chip-open" title="Confidence in the observed temporal pattern, NOT guilt probability">
                  Signal Confidence: {(bundle.summary.confidence * 100).toFixed(0)}%
                </span>
                <span className="chip chip-warning">
                  {bundle.summary.requires_human_review ? "⚠ HUMAN REVIEW REQUIRED" : "INFORMATIONAL"}
                </span>
              </div>
            </div>

            <div style={{ fontSize: 12, color: "var(--text-muted)", lineHeight: 1.6 }}>
              <strong>Institutional Safeguard:</strong> This finding reflects correlated system timestamps and relationship records.
              It does NOT constitute proof of misconduct or fraud. Investigators must evaluate alternative legitimate explanations
              and verify missing evidence before forming conclusions.
            </div>
          </div>
        )}

        {/* Navigation Subtabs */}
        <div className="wb-tabs-bar" style={{ display: "flex", gap: 8, borderBottom: "1px solid var(--border-color)", marginTop: 16, paddingBottom: 8 }}>
          <button
            className={`wb-tab ${activeSection === "overview" ? "active" : ""}`}
            onClick={() => setActiveSection("overview")}
          >
            Overview &amp; Hypotheses
          </button>
          <button
            className={`wb-tab ${activeSection === "timeline" ? "active" : ""}`}
            onClick={() => setActiveSection("timeline")}
          >
            Temporal Timeline ({bundle?.events.length || 0})
          </button>
          <button
            className={`wb-tab ${activeSection === "signals" ? "active" : ""}`}
            onClick={() => setActiveSection("signals")}
          >
            Correlation Signals ({bundle?.signals.length || 0})
          </button>
          <button
            className={`wb-tab ${activeSection === "evidence" ? "active" : ""}`}
            onClick={() => setActiveSection("evidence")}
          >
            Evidence &amp; Gaps
          </button>
          <button
            className={`wb-tab ${activeSection === "relationships" ? "active" : ""}`}
            onClick={() => setActiveSection("relationships")}
          >
            Resolved Entities ({bundle?.relationships.length || 0})
          </button>
        </div>
      </div>

      {loading ? (
        <div className="wb-card" style={{ color: "var(--text-muted)", padding: 30, textAlign: "center" }}>
          Aggregating multi-system events, relationship graph, and signals...
        </div>
      ) : bundle ? (
        <div>
          {/* Section 1: Overview & Competing Hypotheses */}
          {activeSection === "overview" && (
            <div style={{ display: "grid", gridTemplateColumns: "1.2fr 0.8fr", gap: 16 }}>
              <div>
                <div className="wb-card">
                  <h3 className="wb-card-title" style={{ fontSize: 15, marginBottom: 12 }}>
                    Competing Investigation Hypotheses ({bundle.hypotheses.length})
                  </h3>
                  <p className="wb-card-subtitle" style={{ marginBottom: 16 }}>
                    Defensible investigation requires testing mutually exclusive explanations rather than single-metric scores.
                  </p>

                  <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                    {bundle.hypotheses.map((h) => (
                      <div
                        key={h.hypothesis_id}
                        style={{
                          border: "1px solid var(--border-color)",
                          padding: 14,
                          borderRadius: 6,
                          background: "rgba(255,255,255,0.02)",
                        }}
                      >
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 6 }}>
                          <div>
                            <strong style={{ fontSize: 14, color: "var(--text-color)" }}>{h.title}</strong>
                            <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                              ID: {h.hypothesis_id}
                            </div>
                          </div>
                          <span className={`chip ${h.status === "supported" ? "chip-approved" : h.status === "disproven" ? "chip-closed" : "chip-open"}`}>
                            {h.status.toUpperCase()}
                          </span>
                        </div>

                        <p style={{ fontSize: 13, color: "var(--text-muted)", margin: "8px 0" }}>
                          {h.description}
                        </p>

                        <div style={{ fontSize: 12, lineHeight: 1.7 }}>
                          {h.supporting_signal_ids.length > 0 && (
                            <div>
                              <strong style={{ color: "#86efac" }}>Supporting Signals:</strong> {h.supporting_signal_ids.join(", ")}
                            </div>
                          )}
                          {h.contradicting_signal_ids.length > 0 && (
                            <div>
                              <strong style={{ color: "#fca5a5" }}>Contradicting Signals:</strong> {h.contradicting_signal_ids.join(", ")}
                            </div>
                          )}
                          {h.investigator_note && (
                            <div style={{ background: "rgba(255,255,255,0.03)", padding: "6px 10px", borderRadius: 4, marginTop: 6, fontStyle: "italic" }}>
                              <strong>Investigator Note:</strong> {h.investigator_note}
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div>
                {/* Add Hypothesis Form */}
                <div className="wb-card">
                  <h3 className="wb-card-title" style={{ fontSize: 15, marginBottom: 8 }}>
                    Formulate Competing Hypothesis
                  </h3>
                  <p className="wb-card-subtitle" style={{ marginBottom: 16 }}>
                    Record an alternative explanation or testing angle for this case.
                  </p>

                  <form onSubmit={handleCreateHypothesis}>
                    <div style={{ marginBottom: 12 }}>
                      <label style={{ display: "block", fontSize: 12, color: "var(--text-muted)", marginBottom: 4 }}>
                        Hypothesis Title
                      </label>
                      <input
                        type="text"
                        placeholder="e.g. Legitimate Customer Mandate Update"
                        value={newHypoTitle}
                        onChange={(e) => setNewHypoTitle(e.target.value)}
                        required
                        style={{ width: "100%", padding: 8, background: "var(--card-bg)", color: "var(--text-color)", border: "1px solid var(--border-color)", borderRadius: 4 }}
                      />
                    </div>

                    <div style={{ marginBottom: 12 }}>
                      <label style={{ display: "block", fontSize: 12, color: "var(--text-muted)", marginBottom: 4 }}>
                        Description &amp; Reasoning
                      </label>
                      <textarea
                        rows={3}
                        placeholder="Describe why this explanation is plausible..."
                        value={newHypoDesc}
                        onChange={(e) => setNewHypoDesc(e.target.value)}
                        required
                        style={{ width: "100%", padding: 8, background: "var(--card-bg)", color: "var(--text-color)", border: "1px solid var(--border-color)", borderRadius: 4 }}
                      />
                    </div>

                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
                      <div>
                        <label style={{ display: "block", fontSize: 12, color: "var(--text-muted)", marginBottom: 4 }}>
                          Status
                        </label>
                        <select
                          value={newHypoStatus}
                          onChange={(e) => setNewHypoStatus(e.target.value as any)}
                          style={{ width: "100%", padding: 8, background: "var(--card-bg)", color: "var(--text-color)", border: "1px solid var(--border-color)", borderRadius: 4 }}
                        >
                          <option value="open">OPEN</option>
                          <option value="supported">SUPPORTED</option>
                          <option value="weakened">WEAKENED</option>
                          <option value="disproven">DISPROVEN</option>
                        </select>
                      </div>

                      <div>
                        <label style={{ display: "block", fontSize: 12, color: "var(--text-muted)", marginBottom: 4 }}>
                          Confidence: {(newHypoConfidence * 100).toFixed(0)}%
                        </label>
                        <input
                          type="range"
                          min="0"
                          max="1"
                          step="0.05"
                          value={newHypoConfidence}
                          onChange={(e) => setNewHypoConfidence(Number(e.target.value))}
                          style={{ width: "100%", marginTop: 8 }}
                        />
                      </div>
                    </div>

                    <div style={{ marginBottom: 16 }}>
                      <label style={{ display: "block", fontSize: 12, color: "var(--text-muted)", marginBottom: 4 }}>
                        Investigator Observation / Note (Optional)
                      </label>
                      <input
                        type="text"
                        placeholder="e.g. Awaiting branch CCTV or physical ticket"
                        value={newHypoNote}
                        onChange={(e) => setNewHypoNote(e.target.value)}
                        style={{ width: "100%", padding: 8, background: "var(--card-bg)", color: "var(--text-color)", border: "1px solid var(--border-color)", borderRadius: 4 }}
                      />
                    </div>

                    <button className="wb-btn" type="submit" disabled={savingHypo || !newHypoTitle.trim()}>
                      {savingHypo ? "Saving..." : "Add Hypothesis"}
                    </button>
                  </form>
                </div>
              </div>
            </div>
          )}

          {/* Section 2: Temporal Timeline Table */}
          {activeSection === "timeline" && (
            <div className="wb-card">
              <h3 className="wb-card-title" style={{ fontSize: 16, marginBottom: 12 }}>
                Chronological Multi-System Event Sequence
              </h3>
              <p className="wb-card-subtitle" style={{ marginBottom: 16 }}>
                Unified cross-system timeline correlated across Core Banking, IAM, Payments, and CBS Audit logs.
              </p>

              {bundle.events.length === 0 ? (
                <div style={{ color: "var(--text-muted)", padding: 20 }}>No correlated events recorded in this window.</div>
              ) : (
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
                    <thead>
                      <tr style={{ borderBottom: "1px solid var(--border-color)", textAlign: "left", color: "var(--text-muted)" }}>
                        <th style={{ padding: "8px 12px" }}>Timestamp (UTC)</th>
                        <th style={{ padding: "8px 12px" }}>Source System</th>
                        <th style={{ padding: "8px 12px" }}>Event Type</th>
                        <th style={{ padding: "8px 12px" }}>Actor (Staff)</th>
                        <th style={{ padding: "8px 12px" }}>Subject (Target)</th>
                        <th style={{ padding: "8px 12px" }}>Related Entities</th>
                        <th style={{ padding: "8px 12px" }}>Provenance SHA</th>
                      </tr>
                    </thead>
                    <tbody>
                      {bundle.events.map((e) => (
                        <tr key={e.event_id} style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                          <td style={{ padding: "8px 12px", fontFamily: "var(--font-mono)" }}>
                            {new Date(e.event_time).toLocaleString()}
                          </td>
                          <td style={{ padding: "8px 12px" }}>
                            <span className="chip" style={{ fontSize: 11 }}>{e.source_system || "unknown"}</span>
                          </td>
                          <td style={{ padding: "8px 12px", fontWeight: 600 }}>{e.event_type}</td>
                          <td style={{ padding: "8px 12px", fontFamily: "var(--font-mono)", color: "var(--accent-blue)" }}>
                            {e.actor || "—"}
                          </td>
                          <td style={{ padding: "8px 12px", fontFamily: "var(--font-mono)" }}>
                            {e.subject || "—"}
                          </td>
                          <td style={{ padding: "8px 12px", fontSize: 12, color: "var(--text-muted)" }}>
                            {e.entities.join(", ") || "—"}
                          </td>
                          <td style={{ padding: "8px 12px", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" }}>
                            {e.provenance_digest ? e.provenance_digest.slice(0, 12) + "..." : "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* Section 3: Correlation Signals Table */}
          {activeSection === "signals" && (
            <div className="wb-card">
              <h3 className="wb-card-title" style={{ fontSize: 16, marginBottom: 12 }}>
                Detected Cross-System Correlation Signals
              </h3>
              <p className="wb-card-subtitle" style={{ marginBottom: 16 }}>
                Signals represent deterministic temporal patterns across independent bank platforms.
              </p>

              {bundle.signals.length === 0 ? (
                <div style={{ color: "var(--text-muted)", padding: 20 }}>No correlation signals detected for this case.</div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                  {bundle.signals.map((s) => (
                    <div
                      key={s.signal_id}
                      style={{
                        border: "1px solid var(--border-color)",
                        padding: 16,
                        borderRadius: 6,
                        background: "rgba(255,255,255,0.02)",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 8 }}>
                        <div>
                          <strong style={{ fontSize: 15, color: "var(--text-color)" }}>{s.title}</strong>
                          <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                            Signal Type: {s.signal_type} &bull; ID: {s.signal_id}
                          </div>
                        </div>
                        <div style={{ display: "flex", gap: 8 }}>
                          <span className={`chip chip-${s.severity === "high" || s.severity === "critical" ? "closed" : "open"}`}>
                            {s.severity.toUpperCase()}
                          </span>
                          <span className="chip">Pattern Confidence: {(s.confidence * 100).toFixed(0)}%</span>
                        </div>
                      </div>

                      <p style={{ fontSize: 13, color: "var(--text-color)", margin: "8px 0" }}>
                        {s.explanation}
                      </p>

                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginTop: 12, fontSize: 12 }}>
                        <div style={{ background: "rgba(255,255,255,0.02)", padding: 10, borderRadius: 4 }}>
                          <strong style={{ color: "var(--accent-blue)" }}>Alternative Explanations (Plausible Benign Context):</strong>
                          <ul style={{ paddingLeft: 18, margin: "6px 0", color: "var(--text-muted)" }}>
                            {s.alternative_explanations.map((alt, idx) => (
                              <li key={idx}>{alt}</li>
                            ))}
                          </ul>
                        </div>
                        <div style={{ background: "rgba(255,255,255,0.02)", padding: 10, borderRadius: 4 }}>
                          <strong style={{ color: "#fbbf24" }}>Missing Evidence (Required Before Conclusion):</strong>
                          <ul style={{ paddingLeft: 18, margin: "6px 0", color: "var(--text-muted)" }}>
                            {s.missing_evidence.map((miss, idx) => (
                              <li key={idx}><code>{miss}</code></li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Section 4: Evidence & Gaps */}
          {activeSection === "evidence" && (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              <div className="wb-card">
                <h3 className="wb-card-title" style={{ fontSize: 15, marginBottom: 12 }}>
                  Alternative Legitimate Explanations
                </h3>
                <p className="wb-card-subtitle" style={{ marginBottom: 12 }}>
                  Plausible operational rationales that investigators must actively test to avoid false accusations.
                </p>

                {bundle.summary.alternative_explanations.length === 0 ? (
                  <div style={{ color: "var(--text-muted)" }}>None registered.</div>
                ) : (
                  <ul style={{ paddingLeft: 20, color: "var(--text-color)", lineHeight: 1.8, fontSize: 13 }}>
                    {bundle.summary.alternative_explanations.map((alt, idx) => (
                      <li key={idx}>{alt}</li>
                    ))}
                  </ul>
                )}
              </div>

              <div className="wb-card">
                <h3 className="wb-card-title" style={{ fontSize: 15, marginBottom: 12 }}>
                  Missing Evidence Checklist
                </h3>
                <p className="wb-card-subtitle" style={{ marginBottom: 12 }}>
                  Bank source data required to confirm or disprove observed risk hypotheses.
                </p>

                {bundle.summary.missing_evidence.length === 0 ? (
                  <div style={{ color: "var(--text-muted)" }}>All supporting records available.</div>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                    {bundle.summary.missing_evidence.map((item, idx) => (
                      <div
                        key={idx}
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 10,
                          padding: "8px 12px",
                          background: "rgba(255,255,255,0.03)",
                          border: "1px solid var(--border-color)",
                          borderRadius: 4,
                          fontSize: 13,
                        }}
                      >
                        <span style={{ color: "#fbbf24", fontWeight: "bold" }}>☐</span>
                        <code style={{ color: "var(--text-color)" }}>{item}</code>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Section 5: Resolved Entity Relationships */}
          {activeSection === "relationships" && (
            <div className="wb-card">
              <h3 className="wb-card-title" style={{ fontSize: 16, marginBottom: 12 }}>
                Resolved Entity Relationship Graph
              </h3>
              <p className="wb-card-subtitle" style={{ marginBottom: 16 }}>
                Multi-system edges connecting employees, accounts, sessions, devices, and customers.
              </p>

              {bundle.relationships.length === 0 ? (
                <div style={{ color: "var(--text-muted)", padding: 20 }}>No entity relationships resolved for this case.</div>
              ) : (
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
                    <thead>
                      <tr style={{ borderBottom: "1px solid var(--border-color)", textAlign: "left", color: "var(--text-muted)" }}>
                        <th style={{ padding: "8px 12px" }}>Source Entity</th>
                        <th style={{ padding: "8px 12px" }}>Relationship</th>
                        <th style={{ padding: "8px 12px" }}>Target Entity</th>
                        <th style={{ padding: "8px 12px" }}>Confidence</th>
                        <th style={{ padding: "8px 12px" }}>Source System</th>
                        <th style={{ padding: "8px 12px" }}>Last Seen</th>
                      </tr>
                    </thead>
                    <tbody>
                      {bundle.relationships.map((r, idx) => (
                        <tr key={idx} style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                          <td style={{ padding: "8px 12px", fontFamily: "var(--font-mono)" }}>
                            <span style={{ fontSize: 11, color: "var(--text-muted)", display: "block" }}>{r.source_type}</span>
                            {r.source_id}
                          </td>
                          <td style={{ padding: "8px 12px", color: "var(--accent-blue)", fontWeight: 600 }}>
                            {r.relationship_type}
                          </td>
                          <td style={{ padding: "8px 12px", fontFamily: "var(--font-mono)" }}>
                            <span style={{ fontSize: 11, color: "var(--text-muted)", display: "block" }}>{r.target_type}</span>
                            {r.target_id}
                          </td>
                          <td style={{ padding: "8px 12px" }}>
                            <span className="chip" style={{ fontSize: 11 }}>{(r.confidence * 100).toFixed(0)}%</span>
                          </td>
                          <td style={{ padding: "8px 12px" }}>{r.source_system || "—"}</td>
                          <td style={{ padding: "8px 12px", color: "var(--text-muted)" }}>
                            {r.last_seen ? new Date(r.last_seen).toLocaleString() : "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      ) : (
        <div className="wb-card" style={{ color: "var(--text-muted)", padding: 40, textAlign: "center" }}>
          Select a case to inspect its cross-system intelligence bundle.
        </div>
      )}
    </div>
  );
};
export default InvestigationView;
