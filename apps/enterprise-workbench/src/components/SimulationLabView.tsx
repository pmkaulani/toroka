import React, { useEffect, useState } from "react";
import { api } from "../api";
import {
  CaseOutcome,
  CaseSummary,
  Persona,
  SimulationApproval,
  SimulationRun,
  SimulationStrategy,
} from "../types";

interface SimulationLabViewProps {
  currentPersona?: Persona;
}

export const SimulationLabView: React.FC<SimulationLabViewProps> = ({
  currentPersona,
}) => {
  const [subTab, setSubTab] = useState<
    "replay" | "adjudication" | "strategies" | "approvals"
  >("replay");

  // State
  const [strategies, setStrategies] = useState<SimulationStrategy[]>([]);
  const [outcomes, setOutcomes] = useState<CaseOutcome[]>([]);
  const [runs, setRuns] = useState<SimulationRun[]>([]);
  const [approvals, setApprovals] = useState<SimulationApproval[]>([]);
  const [cases, setCases] = useState<CaseSummary[]>([]);

  // Selection & Forms
  const [selectedPropStratId, setSelectedPropStratId] = useState<string>("");
  const [selectedBaseStratId, setSelectedBaseStratId] = useState<string>("");
  const [simulationCutoff, setSimulationCutoff] = useState<string>("");
  const [selectedCohortCase, setSelectedCohortCase] = useState<string>("all");
  const [activeRun, setActiveRun] = useState<SimulationRun | null>(null);

  // Loading & Feedback
  const [loading, setLoading] = useState(false);
  const [runningSimulation, setRunningSimulation] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // New Strategy Form
  const [newStratId, setNewStratId] = useState("");
  const [newStratTitle, setNewStratTitle] = useState("");
  const [newStratDesc, setNewStratDesc] = useState("");
  const [newStratRules, setNewStratRules] = useState<string[]>([
    "employee_access_before_sensitive_change",
  ]);
  const [newStratMinSev, setNewStratMinSev] = useState("medium");
  const [newStratMinConf, setNewStratMinConf] = useState(0.6);
  const [creatingStrat, setCreatingStrat] = useState(false);

  // Adjudication Form
  const [adjCaseId, setAdjCaseId] = useState("");
  const [adjLabel, setAdjLabel] = useState<string>("confirmed_fraud");
  const [adjFirstTime, setAdjFirstTime] = useState("");
  const [adjNotes, setAdjNotes] = useState("");
  const [adjudicating, setAdjudicating] = useState(false);

  // Approval Form
  const [apprStratId, setApprStratId] = useState("");
  const [apprRationale, setApprRationale] = useState("");
  const [submittingAppr, setSubmittingAppr] = useState(false);
  const [reviewNote, setReviewNote] = useState("");
  const [reviewingId, setReviewingId] = useState<string | null>(null);

  const availableRules = [
    {
      id: "employee_access_before_sensitive_change",
      name: "Access Before Sensitive Change",
      desc: "Detects customer profile access followed shortly by sensitive mandate/beneficiary update.",
    },
    {
      id: "privileged_login_before_unusual_transaction",
      name: "Privileged Login Before Unusual Tx",
      desc: "Detects privileged terminal session before unusual credit or transfer posting.",
    },
    {
      id: "role_change_before_sensitive_activity",
      name: "Role Change Before Sensitive Activity",
      desc: "Detects high-privilege IAM assignment right before sensitive customer access.",
    },
    {
      id: "employee_activity_before_reversal_or_closure",
      name: "Activity Before Reversal or Closure",
      desc: "Detects operator interaction before account freeze, closure, or charge reversal.",
    },
    {
      id: "customer_complaint_correlated_employee_activity",
      name: "Customer Complaint Correlated Activity",
      desc: "Correlates CRM dispute or complaint tickets with specific staff actions.",
    },
    {
      id: "authentication_anomaly_with_sensitive_action",
      name: "Auth Anomaly With Sensitive Action",
      desc: "Flags impossible travel, new IP, or anomalous session concurrent with transactional postings.",
    },
  ];

  const loadAllData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [strats, labs, rns, apprs, cList] = await Promise.all([
        api.listSimulationStrategies().catch(() => []),
        api.listCaseOutcomes().catch(() => []),
        api.listSimulationRuns().catch(() => []),
        api.listStrategyApprovals().catch(() => []),
        api.listCases().then((r) => r.items).catch(() => []),
      ]);
      setStrategies(strats);
      setOutcomes(labs);
      setRuns(rns);
      setApprovals(apprs);
      setCases(cList);

      if (strats.length > 0 && !selectedPropStratId) {
        setSelectedPropStratId(strats[0].strategy_id);
      }
      if (rns.length > 0 && !activeRun) {
        setActiveRun(rns[0]);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAllData();
  }, []);

  const handleRunReplay = async () => {
    if (!selectedPropStratId) return;
    setRunningSimulation(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const payload: {
        strategy_id: string;
        baseline_strategy_id?: string;
        simulation_cutoff?: string;
        cohort_case_ids?: string[];
      } = {
        strategy_id: selectedPropStratId,
      };

      if (selectedBaseStratId && selectedBaseStratId !== "none") {
        payload.baseline_strategy_id = selectedBaseStratId;
      }
      if (simulationCutoff.trim()) {
        payload.simulation_cutoff = new Date(simulationCutoff).toISOString();
      }
      if (selectedCohortCase && selectedCohortCase !== "all") {
        payload.cohort_case_ids = [selectedCohortCase];
      }

      const res = await api.executeSimulationRun(payload);
      setActiveRun(res);
      setSuccessMsg(`Historical replay ${res.simulation_id} completed successfully.`);
      const updatedRuns = await api.listSimulationRuns();
      setRuns(updatedRuns);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setRunningSimulation(false);
    }
  };

  const handleCreateStrategy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newStratId.trim() || !newStratTitle.trim()) return;
    setCreatingStrat(true);
    setError(null);
    try {
      const created = await api.createSimulationStrategy({
        strategy_id: newStratId.trim().toLowerCase().replace(/\s+/g, "_"),
        title: newStratTitle.trim(),
        description: newStratDesc.trim(),
        rules_enabled: newStratRules,
        min_severity: newStratMinSev,
        min_confidence: Number(newStratMinConf),
      });
      setSuccessMsg(`Strategy '${created.strategy_id}' v${created.version} registered.`);
      setNewStratId("");
      setNewStratTitle("");
      setNewStratDesc("");
      const updated = await api.listSimulationStrategies();
      setStrategies(updated);
      setSelectedPropStratId(created.strategy_id);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setCreatingStrat(false);
    }
  };

  const handleAdjudicateOutcome = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!adjCaseId.trim()) return;
    setAdjudicating(true);
    setError(null);
    try {
      const res = await api.adjudicateCaseOutcome({
        case_id: adjCaseId.trim(),
        label: adjLabel,
        first_fraud_event_time: adjFirstTime ? new Date(adjFirstTime).toISOString() : null,
        notes: adjNotes.trim() || null,
      });
      setSuccessMsg(`Case '${res.case_id}' ground truth adjudicated as '${res.label}'.`);
      setAdjNotes("");
      const updatedOutcomes = await api.listCaseOutcomes();
      setOutcomes(updatedOutcomes);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setAdjudicating(false);
    }
  };

  const handleRequestApproval = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!apprStratId.trim() || !apprRationale.trim()) return;
    setSubmittingAppr(true);
    setError(null);
    try {
      const res = await api.requestStrategyApproval({
        strategy_id: apprStratId,
        request_rationale: apprRationale.trim(),
        simulation_run_id: activeRun?.simulation_id,
      });
      setSuccessMsg(`Strategy '${res.strategy_id}' submitted for shadow review (${res.approval_id}).`);
      setApprRationale("");
      const [updatedApprs, updatedStrats] = await Promise.all([
        api.listStrategyApprovals(),
        api.listSimulationStrategies(),
      ]);
      setApprovals(updatedApprs);
      setStrategies(updatedStrats);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmittingAppr(false);
    }
  };

  const handleReviewApproval = async (approvalId: string, decision: "approved" | "rejected") => {
    setError(null);
    try {
      const res = await api.reviewStrategyApproval(approvalId, {
        decision,
        notes: reviewNote.trim() || undefined,
      });
      setSuccessMsg(`Approval ${res.approval_id} reviewed: ${res.status.toUpperCase()}.`);
      setReviewingId(null);
      setReviewNote("");
      const [updatedApprs, updatedStrats] = await Promise.all([
        api.listStrategyApprovals(),
        api.listSimulationStrategies(),
      ]);
      setApprovals(updatedApprs);
      setStrategies(updatedStrats);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const toggleRule = (ruleId: string) => {
    if (newStratRules.includes(ruleId)) {
      setNewStratRules(newStratRules.filter((r) => r !== ruleId));
    } else {
      setNewStratRules([...newStratRules, ruleId]);
    }
  };

  const currentSubject = currentPersona?.id || "current_analyst";

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* Top Banner */}
      <div className="wb-card" style={{ borderLeft: "4px solid #a855f7" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10 }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: 1, color: "var(--accent-purple, #a855f7)", fontWeight: 600 }}>
                Phase 8 Counterfactual Investigation Simulator
              </span>
              <span className="chip" style={{ fontSize: 10, background: "rgba(168, 85, 247, 0.15)", color: "#c084fc", borderColor: "#9333ea" }}>
                Deterministic Historical Replay
              </span>
            </div>
            <h2 style={{ fontSize: 20, margin: "4px 0", color: "var(--text-color)" }}>
              Strategy Backtesting &amp; Shadow Evaluation Lab
            </h2>
            <p style={{ margin: "2px 0 0 0", fontSize: 12, color: "var(--text-muted)", maxWidth: 840 }}>
              Safely validate detection policies against ground truth cohorts before bank deployment. Enforces temporal availability cutoffs (<code>available_at</code>) to prevent telemetry hindsight bias, isolates non-accusatory simulations from live cases, and requires dual-control maker-checker approval.
            </p>
          </div>
          <div style={{ textAlign: "right" }}>
            <span className="chip chip-open" style={{ fontSize: 12 }}>
              {outcomes.length} Adjudicated Cases
            </span>
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
              {strategies.length} Strategy Versions Registered
            </div>
          </div>
        </div>

        {/* Tab Navigation */}
        <div style={{ display: "flex", gap: 8, borderTop: "1px solid var(--border-color)", paddingTop: 10, marginTop: 6 }}>
          <button
            className={`wb-tab ${subTab === "replay" ? "active" : ""}`}
            onClick={() => setSubTab("replay")}
          >
            1. Replay &amp; Backtest Comparison
          </button>
          <button
            className={`wb-tab ${subTab === "adjudication" ? "active" : ""}`}
            onClick={() => setSubTab("adjudication")}
          >
            2. Ground Truth Adjudication ({outcomes.length})
          </button>
          <button
            className={`wb-tab ${subTab === "strategies" ? "active" : ""}`}
            onClick={() => setSubTab("strategies")}
          >
            3. Strategy Registry ({strategies.length})
          </button>
          <button
            className={`wb-tab ${subTab === "approvals" ? "active" : ""}`}
            onClick={() => setSubTab("approvals")}
          >
            4. Shadow Promotion Approvals ({approvals.filter((a) => a.status === "pending").length} Pending)
          </button>
        </div>
      </div>

      {error && (
        <div className="wb-card" style={{ borderLeft: "4px solid var(--accent-rose)", color: "#fca5a5", fontSize: 13 }}>
          <strong>Error:</strong> {error}
        </div>
      )}
      {successMsg && (
        <div className="wb-card" style={{ borderLeft: "4px solid #34d399", color: "#34d399", fontSize: 13 }}>
          ✓ {successMsg}
        </div>
      )}

      {/* SUBTAB 1: REPLAY & BACKTEST COMPARISON */}
      {subTab === "replay" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          {/* Setup Panel */}
          <div className="wb-card">
            <h3 className="wb-card-title" style={{ fontSize: 15, marginBottom: 12 }}>
              Replay Configuration &amp; Cohort Selection
            </h3>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr 1fr", gap: 12, alignItems: "flex-end" }}>
              <div>
                <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
                  Proposed Strategy:
                </label>
                <select
                  value={selectedPropStratId}
                  onChange={(e) => setSelectedPropStratId(e.target.value)}
                  style={{ width: "100%", padding: "6px 8px", background: "var(--card-bg)", color: "var(--text-color)", border: "1px solid var(--border-color)", borderRadius: 4, fontSize: 12 }}
                >
                  {strategies.length === 0 && <option value="">No strategies registered</option>}
                  {strategies.map((s) => (
                    <option key={`${s.strategy_id}:v${s.version}`} value={s.strategy_id}>
                      {s.title} (v{s.version}) [{s.strategy_id}]
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
                  Baseline Strategy (for Delta):
                </label>
                <select
                  value={selectedBaseStratId}
                  onChange={(e) => setSelectedBaseStratId(e.target.value)}
                  style={{ width: "100%", padding: "6px 8px", background: "var(--card-bg)", color: "var(--text-color)", border: "1px solid var(--border-color)", borderRadius: 4, fontSize: 12 }}
                >
                  <option value="none">None (Single Strategy Replay)</option>
                  {strategies.map((s) => (
                    <option key={`base:${s.strategy_id}:v${s.version}`} value={s.strategy_id}>
                      {s.title} (v{s.version})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
                  Cohort Case Scope:
                </label>
                <select
                  value={selectedCohortCase}
                  onChange={(e) => setSelectedCohortCase(e.target.value)}
                  style={{ width: "100%", padding: "6px 8px", background: "var(--card-bg)", color: "var(--text-color)", border: "1px solid var(--border-color)", borderRadius: 4, fontSize: 12 }}
                >
                  <option value="all">All Adjudicated Cases ({outcomes.length})</option>
                  {cases.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.focus} ({c.id.slice(0, 8)})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
                  Historical Cutoff (Available At):
                </label>
                <input
                  type="datetime-local"
                  value={simulationCutoff}
                  onChange={(e) => setSimulationCutoff(e.target.value)}
                  placeholder="Optional Cutoff"
                  style={{ width: "100%", padding: "5px 8px", background: "var(--card-bg)", color: "var(--text-color)", border: "1px solid var(--border-color)", borderRadius: 4, fontSize: 12 }}
                />
              </div>

              <div>
                <button
                  className="wb-btn"
                  onClick={handleRunReplay}
                  disabled={runningSimulation || !selectedPropStratId}
                  style={{ width: "100%", padding: "7px 12px", background: "var(--accent-purple, #a855f7)", color: "#fff", fontWeight: 600 }}
                >
                  {runningSimulation ? "Replaying History..." : "▶ Execute Replay"}
                </button>
              </div>
            </div>

            {/* Past runs selector */}
            {runs.length > 0 && (
              <div style={{ marginTop: 12, display: "flex", alignItems: "center", gap: 8, fontSize: 12 }}>
                <span style={{ color: "var(--text-muted)" }}>Past Backtest Runs:</span>
                <select
                  value={activeRun?.simulation_id || ""}
                  onChange={(e) => {
                    const found = runs.find((r) => r.simulation_id === e.target.value);
                    if (found) setActiveRun(found);
                  }}
                  style={{ padding: "4px 8px", background: "var(--card-bg)", color: "var(--text-color)", border: "1px solid var(--border-color)", borderRadius: 4, fontSize: 11 }}
                >
                  {runs.map((r) => (
                    <option key={r.simulation_id} value={r.simulation_id}>
                      {r.simulation_id} ({r.strategy_id} v{r.strategy_version} • {(r.metrics.precision * 100).toFixed(0)}% prec / {(r.metrics.recall * 100).toFixed(0)}% rec)
                    </option>
                  ))}
                </select>
                {loading && <span style={{ color: "var(--text-muted)", fontSize: 11 }}>Syncing...</span>}
              </div>
            )}

            {/* Ingestion availability note */}
            <div style={{ marginTop: 10, fontSize: 11, color: "var(--text-muted)" }}>
              ℹ️ <strong>Temporal Ingestion Cutoff:</strong> Observations are only visible at simulated time T if <code>available_at &le; T</code>. Events ingested after the cutoff are automatically filtered out to reflect true telemetry latency.
            </div>
          </div>

          {/* Active Replay Results */}
          {activeRun && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              {/* Performance Cards Grid */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 12 }}>
                {/* Precision Card */}
                <div className="wb-card" style={{ textAlign: "center", padding: 14 }}>
                  <span style={{ fontSize: 11, textTransform: "uppercase", color: "var(--text-muted)", fontWeight: 600 }}>Precision</span>
                  <div style={{ fontSize: 24, fontWeight: 700, margin: "4px 0", color: "var(--text-color)" }}>
                    {(activeRun.metrics.precision * 100).toFixed(1)}%
                  </div>
                  {activeRun.delta && (
                    <span className="chip" style={{ fontSize: 10, color: activeRun.delta.precision_diff >= 0 ? "#34d399" : "#fca5a5" }}>
                      {activeRun.delta.precision_diff >= 0 ? "+" : ""}{(activeRun.delta.precision_diff * 100).toFixed(1)}% vs Base
                    </span>
                  )}
                  <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 4 }}>TP / (TP + FP)</div>
                </div>

                {/* Recall Card */}
                <div className="wb-card" style={{ textAlign: "center", padding: 14 }}>
                  <span style={{ fontSize: 11, textTransform: "uppercase", color: "var(--text-muted)", fontWeight: 600 }}>Recall</span>
                  <div style={{ fontSize: 24, fontWeight: 700, margin: "4px 0", color: "var(--text-color)" }}>
                    {(activeRun.metrics.recall * 100).toFixed(1)}%
                  </div>
                  {activeRun.delta && (
                    <span className="chip" style={{ fontSize: 10, color: activeRun.delta.recall_diff >= 0 ? "#34d399" : "#fca5a5" }}>
                      {activeRun.delta.recall_diff >= 0 ? "+" : ""}{(activeRun.delta.recall_diff * 100).toFixed(1)}% vs Base
                    </span>
                  )}
                  <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 4 }}>TP / (TP + FN)</div>
                </div>

                {/* Workload / Alerts Card */}
                <div className="wb-card" style={{ textAlign: "center", padding: 14 }}>
                  <span style={{ fontSize: 11, textTransform: "uppercase", color: "var(--text-muted)", fontWeight: 600 }}>Analyst Workload</span>
                  <div style={{ fontSize: 24, fontWeight: 700, margin: "4px 0", color: "var(--text-color)" }}>
                    {activeRun.metrics.total_alerts} Alerts
                  </div>
                  {activeRun.delta && (
                    <span className="chip" style={{ fontSize: 10, color: activeRun.delta.alert_volume_diff <= 0 ? "#34d399" : "#fbbf24" }}>
                      {activeRun.delta.alert_volume_diff >= 0 ? "+" : ""}{activeRun.delta.alert_volume_diff} Alerts vs Base
                    </span>
                  )}
                  <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 4 }}>{activeRun.metrics.alerted_cases} Cases Alerted</div>
                </div>

                {/* Detection Delay Card */}
                <div className="wb-card" style={{ textAlign: "center", padding: 14 }}>
                  <span style={{ fontSize: 11, textTransform: "uppercase", color: "var(--text-muted)", fontWeight: 600 }}>Mean Detection Delay</span>
                  <div style={{ fontSize: 22, fontWeight: 700, margin: "4px 0", color: "var(--text-color)" }}>
                    {activeRun.metrics.mean_detection_delay_seconds !== null && activeRun.metrics.mean_detection_delay_seconds !== undefined
                      ? `${(activeRun.metrics.mean_detection_delay_seconds / 60).toFixed(1)}m`
                      : "—"}
                  </div>
                  {activeRun.delta?.detection_delay_diff_seconds !== null && activeRun.delta?.detection_delay_diff_seconds !== undefined && (
                    <span className="chip" style={{ fontSize: 10, color: activeRun.delta.detection_delay_diff_seconds <= 0 ? "#34d399" : "#fca5a5" }}>
                      {activeRun.delta.detection_delay_diff_seconds <= 0 ? "" : "+"}
                      {(activeRun.delta.detection_delay_diff_seconds / 60).toFixed(1)}m vs Base
                    </span>
                  )}
                  <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 4 }}>Time from 1st event to alert</div>
                </div>

                {/* Label Coverage Card */}
                <div className="wb-card" style={{ textAlign: "center", padding: 14 }}>
                  <span style={{ fontSize: 11, textTransform: "uppercase", color: "var(--text-muted)", fontWeight: 600 }}>Label Coverage</span>
                  <div style={{ fontSize: 24, fontWeight: 700, margin: "4px 0", color: "var(--text-color)" }}>
                    {activeRun.metrics.label_coverage_pct.toFixed(0)}%
                  </div>
                  <span className="chip" style={{ fontSize: 10 }}>
                    {activeRun.metrics.labelled_cases} of {activeRun.metrics.total_cases_evaluated} Cases
                  </span>
                  <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 4 }}>
                    {activeRun.metrics.inconclusive_cases} Inconc • {activeRun.metrics.unlabelled_cases} Unlabelled
                  </div>
                </div>
              </div>

              {/* Narrative Summary Banner */}
              {activeRun.delta && (
                <div className="wb-card" style={{ background: "rgba(168, 85, 247, 0.08)", border: "1px solid rgba(168, 85, 247, 0.3)" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <div>
                      <strong style={{ color: "#c084fc", fontSize: 13 }}>Institutional Performance Comparison:</strong>
                      <p style={{ margin: "4px 0 0 0", fontSize: 12, color: "var(--text-color)" }}>
                        {activeRun.delta.summary}
                      </p>
                    </div>
                    {activeRun.delayed_events_filtered > 0 && (
                      <span className="chip chip-warning" style={{ fontSize: 11 }}>
                        ⏱ {activeRun.delayed_events_filtered} Ingestion-Delayed Events Filtered Out
                      </span>
                    )}
                  </div>
                </div>
              )}

              {/* Confusion Matrix & Case Ground Truth Breakdown */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                {/* Confusion Matrix Table */}
                <div className="wb-card">
                  <h4 style={{ fontSize: 14, marginBottom: 8, color: "var(--text-color)" }}>
                    Ground Truth Confusion Matrix
                  </h4>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                    <thead>
                      <tr style={{ borderBottom: "1px solid var(--border-color)", textAlign: "left", color: "var(--text-muted)" }}>
                        <th style={{ padding: "6px 8px" }}>Ground Truth</th>
                        <th style={{ padding: "6px 8px" }}>Alerted by Strategy</th>
                        <th style={{ padding: "6px 8px" }}>Not Alerted</th>
                        <th style={{ padding: "6px 8px" }}>Subtotal</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                        <td style={{ padding: "6px 8px", fontWeight: 600, color: "#fca5a5" }}>Confirmed Fraud</td>
                        <td style={{ padding: "6px 8px", color: "#34d399", fontWeight: 600 }}>
                          {activeRun.metrics.true_positives} (TP)
                        </td>
                        <td style={{ padding: "6px 8px", color: "#fca5a5", fontWeight: 600 }}>
                          {activeRun.metrics.false_negatives} (FN)
                        </td>
                        <td style={{ padding: "6px 8px", fontFamily: "var(--font-mono)" }}>
                          {activeRun.metrics.true_positives + activeRun.metrics.false_negatives}
                        </td>
                      </tr>
                      <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                        <td style={{ padding: "6px 8px", fontWeight: 600, color: "#34d399" }}>Confirmed Legitimate</td>
                        <td style={{ padding: "6px 8px", color: "#fbbf24", fontWeight: 600 }}>
                          {activeRun.metrics.false_positives} (FP)
                        </td>
                        <td style={{ padding: "6px 8px", color: "#34d399", fontWeight: 600 }}>
                          {activeRun.metrics.true_negatives} (TN)
                        </td>
                        <td style={{ padding: "6px 8px", fontFamily: "var(--font-mono)" }}>
                          {activeRun.metrics.false_positives + activeRun.metrics.true_negatives}
                        </td>
                      </tr>
                      <tr style={{ background: "rgba(255,255,255,0.02)" }}>
                        <td style={{ padding: "6px 8px", color: "var(--text-muted)" }}>Inconclusive / Unlabelled *</td>
                        <td style={{ padding: "6px 8px", color: "var(--text-muted)" }}>
                          {activeRun.metrics.inconclusive_cases_alerted + activeRun.metrics.unlabelled_cases_alerted} Alerted
                        </td>
                        <td style={{ padding: "6px 8px", color: "var(--text-muted)" }}>
                          {activeRun.metrics.inconclusive_cases + activeRun.metrics.unlabelled_cases - (activeRun.metrics.inconclusive_cases_alerted + activeRun.metrics.unlabelled_cases_alerted)} Quiet
                        </td>
                        <td style={{ padding: "6px 8px", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
                          {activeRun.metrics.inconclusive_cases + activeRun.metrics.unlabelled_cases}
                        </td>
                      </tr>
                    </tbody>
                  </table>
                  <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 8 }}>
                    * Inconclusive and unlabelled cases are tracked separately and excluded from precision and recall calculations to prevent unverified assumptions from biasing strategy scores.
                  </div>
                </div>

                {/* Replay Metadata & Audit Details */}
                <div className="wb-card">
                  <h4 style={{ fontSize: 14, marginBottom: 8, color: "var(--text-color)" }}>
                    Simulation Execution Trace
                  </h4>
                  <div style={{ display: "flex", flexDirection: "column", gap: 6, fontSize: 12 }}>
                    <div>
                      <span style={{ color: "var(--text-muted)", width: 140, display: "inline-block" }}>Simulation Run ID:</span>
                      <code style={{ color: "var(--accent-blue)" }}>{activeRun.simulation_id}</code>
                    </div>
                    <div>
                      <span style={{ color: "var(--text-muted)", width: 140, display: "inline-block" }}>Strategy Evaluated:</span>
                      <strong>{activeRun.strategy_id}</strong> (version {activeRun.strategy_version})
                    </div>
                    {activeRun.baseline_strategy_id && (
                      <div>
                        <span style={{ color: "var(--text-muted)", width: 140, display: "inline-block" }}>Baseline Policy:</span>
                        <strong>{activeRun.baseline_strategy_id}</strong> (version {activeRun.baseline_strategy_version})
                      </div>
                    )}
                    <div>
                      <span style={{ color: "var(--text-muted)", width: 140, display: "inline-block" }}>Replay Executor:</span>
                      <span>{activeRun.executed_by}</span>
                    </div>
                    <div>
                      <span style={{ color: "var(--text-muted)", width: 140, display: "inline-block" }}>Executed At:</span>
                      <span>{new Date(activeRun.executed_at).toLocaleString()}</span>
                    </div>
                    <div>
                      <span style={{ color: "var(--text-muted)", width: 140, display: "inline-block" }}>Events Replayed:</span>
                      <span>{activeRun.total_events_replayed} canonical events</span>
                    </div>
                    <div>
                      <span style={{ color: "var(--text-muted)", width: 140, display: "inline-block" }}>Ingestion Filtered:</span>
                      <span>{activeRun.delayed_events_filtered} delayed events excluded</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Case-Level Detections Breakdown */}
              <div className="wb-card">
                <h4 style={{ fontSize: 15, marginBottom: 12 }}>
                  Cohort Case-Level Detections &amp; Audit Trace
                </h4>
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                    <thead>
                      <tr style={{ borderBottom: "1px solid var(--border-color)", textAlign: "left", color: "var(--text-muted)" }}>
                        <th style={{ padding: "6px 8px" }}>Case ID</th>
                        <th style={{ padding: "6px 8px" }}>Ground Truth</th>
                        <th style={{ padding: "6px 8px" }}>Strategy Alert</th>
                        <th style={{ padding: "6px 8px" }}>Detection Details</th>
                        <th style={{ padding: "6px 8px" }}>First Detection Time</th>
                        <th style={{ padding: "6px 8px" }}>Evaluation Result</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(activeRun.case_detections).map(([caseId, dets]) => {
                        const outcome = outcomes.find((o) => o.case_id === caseId);
                        const label = outcome?.label || "unlabelled";
                        const isAlerted = dets.length > 0;

                        let evalTag = "UNLABELLED";
                        let evalColor = "var(--text-muted)";
                        if (label === "confirmed_fraud") {
                          evalTag = isAlerted ? "TRUE POSITIVE (TP)" : "FALSE NEGATIVE (FN)";
                          evalColor = isAlerted ? "#34d399" : "#fca5a5";
                        } else if (label === "confirmed_legitimate") {
                          evalTag = isAlerted ? "FALSE POSITIVE (FP)" : "TRUE NEGATIVE (TN)";
                          evalColor = isAlerted ? "#fbbf24" : "#34d399";
                        } else if (label === "inconclusive") {
                          evalTag = isAlerted ? "INCONCLUSIVE (Alerted)" : "INCONCLUSIVE (Quiet)";
                        }

                        return (
                          <tr key={caseId} style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                            <td style={{ padding: "6px 8px", fontFamily: "var(--font-mono)", color: "var(--accent-blue)" }}>
                              {caseId.slice(0, 12)}...
                            </td>
                            <td style={{ padding: "6px 8px" }}>
                              <span className="chip" style={{ fontSize: 10 }}>
                                {label.toUpperCase()}
                              </span>
                            </td>
                            <td style={{ padding: "6px 8px", fontWeight: 600 }}>
                              {isAlerted ? (
                                <span style={{ color: "var(--accent-amber)" }}>🚨 {dets.length} Alert(s)</span>
                              ) : (
                                <span style={{ color: "var(--text-muted)" }}>— Quiet</span>
                              )}
                            </td>
                            <td style={{ padding: "6px 8px", maxWidth: 320 }}>
                              {dets.length === 0 ? (
                                <span style={{ color: "var(--text-muted)" }}>No triggers fired.</span>
                              ) : (
                                dets.map((d, i) => (
                                  <div key={i} style={{ marginBottom: 2 }}>
                                    <strong>{d.rule_name}</strong> ({(d.confidence * 100).toFixed(0)}% conf): {d.explanation}
                                  </div>
                                ))
                              )}
                            </td>
                            <td style={{ padding: "6px 8px", fontFamily: "var(--font-mono)", fontSize: 11 }}>
                              {dets.length > 0 ? new Date(dets[0].detected_at).toLocaleTimeString() : "—"}
                            </td>
                            <td style={{ padding: "6px 8px", fontWeight: 600, color: evalColor }}>
                              {evalTag}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* SUBTAB 2: GROUND TRUTH ADJUDICATION */}
      {subTab === "adjudication" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: 16 }}>
          {/* Adjudicate Form */}
          <div className="wb-card">
            <h3 className="wb-card-title" style={{ fontSize: 15, marginBottom: 12 }}>
              Adjudicate Case Ground Truth
            </h3>
            <p className="wb-card-subtitle" style={{ marginBottom: 12 }}>
              Ground truth classifications are the foundation of trustworthy strategy simulation. Never assign fraud guilt without independent corroboration.
            </p>
            <form onSubmit={handleAdjudicateOutcome} style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <div>
                <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
                  Case ID:
                </label>
                <input
                  type="text"
                  placeholder="Case UUID or select..."
                  value={adjCaseId}
                  onChange={(e) => setAdjCaseId(e.target.value)}
                  style={{ width: "100%", padding: "6px 8px", background: "var(--card-bg)", color: "var(--text-color)", border: "1px solid var(--border-color)", borderRadius: 4, fontSize: 12 }}
                  required
                />
              </div>

              <div>
                <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
                  Adjudicated Outcome Label:
                </label>
                <select
                  value={adjLabel}
                  onChange={(e) => setAdjLabel(e.target.value)}
                  style={{ width: "100%", padding: "6px 8px", background: "var(--card-bg)", color: "var(--text-color)", border: "1px solid var(--border-color)", borderRadius: 4, fontSize: 12 }}
                >
                  <option value="confirmed_fraud">confirmed_fraud (Corroborated by independent evidence)</option>
                  <option value="confirmed_legitimate">confirmed_legitimate (Verified legitimate operation)</option>
                  <option value="inconclusive">inconclusive (Evidence debt or ambiguous findings)</option>
                  <option value="unlabelled">unlabelled (Pending investigator adjudication)</option>
                </select>
              </div>

              <div>
                <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
                  First Fraud Event Timestamp (for detection delay measurement):
                </label>
                <input
                  type="datetime-local"
                  value={adjFirstTime}
                  onChange={(e) => setAdjFirstTime(e.target.value)}
                  style={{ width: "100%", padding: "6px 8px", background: "var(--card-bg)", color: "var(--text-color)", border: "1px solid var(--border-color)", borderRadius: 4, fontSize: 12 }}
                />
              </div>

              <div>
                <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
                  Adjudication Rationale / Notes:
                </label>
                <textarea
                  rows={3}
                  value={adjNotes}
                  onChange={(e) => setAdjNotes(e.target.value)}
                  placeholder="Supporting rationale and external source verification..."
                  style={{ width: "100%", padding: "6px 8px", background: "var(--card-bg)", color: "var(--text-color)", border: "1px solid var(--border-color)", borderRadius: 4, fontSize: 12 }}
                />
              </div>

              <button
                type="submit"
                className="wb-btn"
                disabled={adjudicating || !adjCaseId.trim()}
                style={{ padding: "8px 12px", background: "var(--accent-purple, #a855f7)", color: "#fff", fontWeight: 600, marginTop: 4 }}
              >
                {adjudicating ? "Recording Adjudication..." : "Record Ground Truth"}
              </button>
            </form>
          </div>

          {/* Adjudicated Cases List */}
          <div className="wb-card">
            <h3 className="wb-card-title" style={{ fontSize: 15, marginBottom: 12 }}>
              Adjudicated Cases Ground Truth ({outcomes.length})
            </h3>
            {outcomes.length === 0 ? (
              <div style={{ color: "var(--text-muted)", padding: 20 }}>No cases have been adjudicated yet.</div>
            ) : (
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                  <thead>
                    <tr style={{ borderBottom: "1px solid var(--border-color)", textAlign: "left", color: "var(--text-muted)" }}>
                      <th style={{ padding: "6px 8px" }}>Case ID</th>
                      <th style={{ padding: "6px 8px" }}>Label</th>
                      <th style={{ padding: "6px 8px" }}>Adjudicated By</th>
                      <th style={{ padding: "6px 8px" }}>Timestamp</th>
                      <th style={{ padding: "6px 8px" }}>Notes</th>
                    </tr>
                  </thead>
                  <tbody>
                    {outcomes.map((o) => (
                      <tr key={o.case_id} style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                        <td style={{ padding: "6px 8px", fontFamily: "var(--font-mono)", color: "var(--accent-blue)" }}>
                          {o.case_id.slice(0, 16)}...
                        </td>
                        <td style={{ padding: "6px 8px" }}>
                          <span
                            className="chip"
                            style={{
                              color:
                                o.label === "confirmed_fraud"
                                  ? "#fca5a5"
                                  : o.label === "confirmed_legitimate"
                                  ? "#34d399"
                                  : "var(--text-muted)",
                            }}
                          >
                            {o.label.toUpperCase()}
                          </span>
                        </td>
                        <td style={{ padding: "6px 8px" }}>{o.adjudicated_by}</td>
                        <td style={{ padding: "6px 8px", fontSize: 11 }}>
                          {new Date(o.adjudicated_at).toLocaleDateString()}
                        </td>
                        <td style={{ padding: "6px 8px", maxWidth: 240, color: "var(--text-muted)" }}>
                          {o.notes || "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* SUBTAB 3: STRATEGY REGISTRY & VERSIONS */}
      {subTab === "strategies" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: 16 }}>
          {/* Create Strategy Form */}
          <div className="wb-card">
            <h3 className="wb-card-title" style={{ fontSize: 15, marginBottom: 12 }}>
              Author Immutable Detection Strategy
            </h3>
            <form onSubmit={handleCreateStrategy} style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <div>
                <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
                  Strategy ID (Slug):
                </label>
                <input
                  type="text"
                  placeholder="e.g. strat_insider_rules"
                  value={newStratId}
                  onChange={(e) => setNewStratId(e.target.value)}
                  style={{ width: "100%", padding: "6px 8px", background: "var(--card-bg)", color: "var(--text-color)", border: "1px solid var(--border-color)", borderRadius: 4, fontSize: 12 }}
                  required
                />
              </div>

              <div>
                <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
                  Title:
                </label>
                <input
                  type="text"
                  placeholder="Strategy title..."
                  value={newStratTitle}
                  onChange={(e) => setNewStratTitle(e.target.value)}
                  style={{ width: "100%", padding: "6px 8px", background: "var(--card-bg)", color: "var(--text-color)", border: "1px solid var(--border-color)", borderRadius: 4, fontSize: 12 }}
                  required
                />
              </div>

              <div>
                <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
                  Description:
                </label>
                <textarea
                  rows={2}
                  value={newStratDesc}
                  onChange={(e) => setNewStratDesc(e.target.value)}
                  placeholder="Institutional rationale and intended fraud pattern..."
                  style={{ width: "100%", padding: "6px 8px", background: "var(--card-bg)", color: "var(--text-color)", border: "1px solid var(--border-color)", borderRadius: 4, fontSize: 12 }}
                />
              </div>

              <div>
                <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 6 }}>
                  Active Correlation Rules:
                </label>
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  {availableRules.map((r) => (
                    <label
                      key={r.id}
                      style={{
                        display: "flex",
                        alignItems: "flex-start",
                        gap: 8,
                        fontSize: 12,
                        padding: "6px 8px",
                        background: newStratRules.includes(r.id) ? "rgba(168, 85, 247, 0.1)" : "rgba(255,255,255,0.02)",
                        borderRadius: 4,
                        border: "1px solid var(--border-color)",
                        cursor: "pointer",
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={newStratRules.includes(r.id)}
                        onChange={() => toggleRule(r.id)}
                        style={{ marginTop: 2 }}
                      />
                      <div>
                        <strong>{r.name}</strong>
                        <div style={{ fontSize: 10, color: "var(--text-muted)" }}>{r.desc}</div>
                      </div>
                    </label>
                  ))}
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                <div>
                  <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
                    Min Severity:
                  </label>
                  <select
                    value={newStratMinSev}
                    onChange={(e) => setNewStratMinSev(e.target.value)}
                    style={{ width: "100%", padding: "6px 8px", background: "var(--card-bg)", color: "var(--text-color)", border: "1px solid var(--border-color)", borderRadius: 4, fontSize: 12 }}
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>

                <div>
                  <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
                    Min Confidence: {(newStratMinConf * 100).toFixed(0)}%
                  </label>
                  <input
                    type="range"
                    min="0.1"
                    max="1.0"
                    step="0.05"
                    value={newStratMinConf}
                    onChange={(e) => setNewStratMinConf(Number(e.target.value))}
                    style={{ width: "100%", marginTop: 6 }}
                  />
                </div>
              </div>

              <button
                type="submit"
                className="wb-btn"
                disabled={creatingStrat || !newStratId.trim() || !newStratTitle.trim()}
                style={{ padding: "8px 12px", background: "var(--accent-purple, #a855f7)", color: "#fff", fontWeight: 600, marginTop: 4 }}
              >
                {creatingStrat ? "Saving Version..." : "Register Strategy Version"}
              </button>
            </form>
          </div>

          {/* Registered Strategies List */}
          <div className="wb-card">
            <h3 className="wb-card-title" style={{ fontSize: 15, marginBottom: 12 }}>
              Strategy Registry ({strategies.length})
            </h3>
            {strategies.length === 0 ? (
              <div style={{ color: "var(--text-muted)", padding: 20 }}>No detection strategies registered yet.</div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {strategies.map((s) => (
                  <div
                    key={`${s.strategy_id}:v${s.version}`}
                    style={{
                      border: "1px solid var(--border-color)",
                      background: "rgba(255,255,255,0.02)",
                      borderRadius: 6,
                      padding: 12,
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                      <div>
                        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                          <strong style={{ fontSize: 14 }}>{s.title}</strong>
                          <span className="chip" style={{ fontSize: 10 }}>
                            v{s.version}
                          </span>
                          <span
                            className="chip"
                            style={{
                              fontSize: 10,
                              color:
                                s.status === "approved"
                                  ? "#34d399"
                                  : s.status === "pending_review"
                                  ? "#fbbf24"
                                  : "var(--text-muted)",
                            }}
                          >
                            {s.status.toUpperCase()}
                          </span>
                        </div>
                        <div style={{ fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--accent-blue)", marginTop: 2 }}>
                          {s.strategy_id}
                        </div>
                      </div>
                      <div style={{ textAlign: "right", fontSize: 11, color: "var(--text-muted)" }}>
                        Author: {s.created_by} &bull; {new Date(s.created_at).toLocaleDateString()}
                      </div>
                    </div>

                    <p style={{ fontSize: 12, color: "var(--text-muted)", margin: "6px 0 8px 0" }}>
                      {s.description || "No description provided."}
                    </p>

                    <div style={{ display: "flex", flexWrap: "wrap", gap: 6, alignItems: "center", fontSize: 11 }}>
                      <span style={{ color: "var(--text-muted)" }}>Rules:</span>
                      {s.rules_enabled.length === 0 ? (
                        <span style={{ color: "var(--text-muted)" }}>None (Empty Policy)</span>
                      ) : (
                        s.rules_enabled.map((r, i) => (
                          <span key={i} className="chip" style={{ fontSize: 10, background: "rgba(0,0,0,0.3)" }}>
                            {r}
                          </span>
                        ))
                      )}
                      <span style={{ marginLeft: "auto", color: "var(--text-muted)" }}>
                        Min Sev: {s.min_severity} &bull; Min Conf: {(s.min_confidence * 100).toFixed(0)}%
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* SUBTAB 4: SHADOW DEPLOYMENT APPROVALS (Dual-Control Maker-Checker) */}
      {subTab === "approvals" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: 16 }}>
          {/* Submit Request Form */}
          <div className="wb-card">
            <h3 className="wb-card-title" style={{ fontSize: 15, marginBottom: 12 }}>
              Submit Strategy for Shadow Promotion
            </h3>
            <p className="wb-card-subtitle" style={{ marginBottom: 12 }}>
              Dual control enforcement: A strategy author cannot approve their own promotion request. A different user with Authoriser or Admin privileges must review validation results.
            </p>
            <form onSubmit={handleRequestApproval} style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <div>
                <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
                  Strategy to Promote:
                </label>
                <select
                  value={apprStratId}
                  onChange={(e) => setApprStratId(e.target.value)}
                  style={{ width: "100%", padding: "6px 8px", background: "var(--card-bg)", color: "var(--text-color)", border: "1px solid var(--border-color)", borderRadius: 4, fontSize: 12 }}
                  required
                >
                  <option value="">Select strategy...</option>
                  {strategies.map((s) => (
                    <option key={`appr:${s.strategy_id}:v${s.version}`} value={s.strategy_id}>
                      {s.title} (v{s.version}) [{s.status}]
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
                  Promotion Rationale &amp; Backtesting Validation Summary:
                </label>
                <textarea
                  rows={4}
                  value={apprRationale}
                  onChange={(e) => setApprRationale(e.target.value)}
                  placeholder="Explain why this detection strategy should be promoted to shadow execution, citing historical replay recall and precision..."
                  style={{ width: "100%", padding: "6px 8px", background: "var(--card-bg)", color: "var(--text-color)", border: "1px solid var(--border-color)", borderRadius: 4, fontSize: 12 }}
                  required
                />
              </div>

              {activeRun && (
                <div style={{ fontSize: 11, color: "var(--text-muted)", background: "rgba(0,0,0,0.2)", padding: 8, borderRadius: 4 }}>
                  🔗 Will link active backtest run: <code>{activeRun.simulation_id}</code> ({(activeRun.metrics.precision * 100).toFixed(0)}% prec / {(activeRun.metrics.recall * 100).toFixed(0)}% rec)
                </div>
              )}

              <button
                type="submit"
                className="wb-btn"
                disabled={submittingAppr || !apprStratId || !apprRationale.trim()}
                style={{ padding: "8px 12px", background: "var(--accent-purple, #a855f7)", color: "#fff", fontWeight: 600, marginTop: 4 }}
              >
                {submittingAppr ? "Submitting..." : "Submit for Dual Review"}
              </button>
            </form>
          </div>

          {/* Approvals Review Pipeline */}
          <div className="wb-card">
            <h3 className="wb-card-title" style={{ fontSize: 15, marginBottom: 12 }}>
              Dual-Control Review Pipeline ({approvals.length})
            </h3>
            {approvals.length === 0 ? (
              <div style={{ color: "var(--text-muted)", padding: 20 }}>No strategy promotion requests submitted.</div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {approvals.map((a) => {
                  const isRequester = a.requester_subject === currentSubject;
                  return (
                    <div
                      key={a.approval_id}
                      style={{
                        border: "1px solid var(--border-color)",
                        background: a.status === "pending" ? "rgba(251, 191, 36, 0.05)" : "rgba(255,255,255,0.02)",
                        borderRadius: 6,
                        padding: 12,
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                        <div>
                          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                            <strong style={{ fontSize: 14 }}>{a.strategy_id}</strong>
                            <span className="chip" style={{ fontSize: 10 }}>v{a.strategy_version}</span>
                            <span
                              className="chip"
                              style={{
                                fontSize: 10,
                                color:
                                  a.status === "approved"
                                    ? "#34d399"
                                    : a.status === "rejected"
                                    ? "#fca5a5"
                                    : "#fbbf24",
                              }}
                            >
                              {a.status.toUpperCase()}
                            </span>
                          </div>
                          <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
                            Requested by: <strong>{a.requester_subject}</strong> &bull; {new Date(a.requested_at).toLocaleString()}
                          </div>
                        </div>
                      </div>

                      <div style={{ fontSize: 12, margin: "8px 0", color: "var(--text-color)" }}>
                        <strong>Rationale:</strong> {a.request_rationale}
                      </div>

                      {a.simulation_run_id && (
                        <div style={{ fontSize: 11, color: "var(--accent-blue)", marginBottom: 8 }}>
                          Validated Run: <code>{a.simulation_run_id}</code>
                        </div>
                      )}

                      {/* Review State */}
                      {a.status === "pending" ? (
                        <div style={{ borderTop: "1px solid rgba(255,255,255,0.05)", paddingTop: 8, marginTop: 8 }}>
                          {isRequester ? (
                            <div style={{ fontSize: 11, color: "var(--accent-amber)" }}>
                              ⚠️ <strong>Dual Control Active:</strong> You requested this promotion ({a.requester_subject}). A different officer must complete the checker review.
                            </div>
                          ) : reviewingId === a.approval_id ? (
                            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                              <input
                                type="text"
                                placeholder="Review notes / risk governance rationale..."
                                value={reviewNote}
                                onChange={(e) => setReviewNote(e.target.value)}
                                style={{ padding: "4px 8px", fontSize: 12, background: "var(--card-bg)", color: "var(--text-color)", border: "1px solid var(--border-color)", borderRadius: 4 }}
                              />
                              <div style={{ display: "flex", gap: 8 }}>
                                <button
                                  className="wb-btn"
                                  onClick={() => handleReviewApproval(a.approval_id, "approved")}
                                  style={{ padding: "4px 10px", fontSize: 11, background: "#059669", color: "#fff" }}
                                >
                                  ✓ Approve Strategy
                                </button>
                                <button
                                  className="wb-btn"
                                  onClick={() => handleReviewApproval(a.approval_id, "rejected")}
                                  style={{ padding: "4px 10px", fontSize: 11, background: "#dc2626", color: "#fff" }}
                                >
                                  ✗ Reject Strategy
                                </button>
                                <button
                                  className="wb-btn"
                                  onClick={() => setReviewingId(null)}
                                  style={{ padding: "4px 8px", fontSize: 11 }}
                                >
                                  Cancel
                                </button>
                              </div>
                            </div>
                          ) : (
                            <button
                              className="wb-btn"
                              onClick={() => {
                                setReviewingId(a.approval_id);
                                setReviewNote("");
                              }}
                              style={{ padding: "4px 10px", fontSize: 11 }}
                            >
                              Review &amp; Authorise
                            </button>
                          )}
                        </div>
                      ) : (
                        <div style={{ fontSize: 11, color: "var(--text-muted)", borderTop: "1px solid rgba(255,255,255,0.05)", paddingTop: 6 }}>
                          Reviewed by <strong>{a.reviewer_subject}</strong> on {a.reviewed_at ? new Date(a.reviewed_at).toLocaleString() : "—"}: {a.review_notes || "No notes."}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default SimulationLabView;
