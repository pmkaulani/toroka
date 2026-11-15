import React, { useEffect, useState } from "react";
import { api } from "../api";
import {
  Connector,
  ConnectorHealth,
  IntegrationJob,
  QualityAssessment,
  ReconciliationReport,
} from "../types";

export const IntegrationsView: React.FC = () => {
  const [subTab, setSubTab] = useState<"connectors" | "jobs" | "reconciliation" | "quality">("connectors");
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [jobs, setJobs] = useState<IntegrationJob[]>([]);
  const [quality, setQuality] = useState<QualityAssessment | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [healthMap, setHealthMap] = useState<Record<string, ConnectorHealth>>({});

  // Reconciliation state
  const [reconConnectorId, setReconConnectorId] = useState<string>("");
  const [reconExpectedCount, setReconExpectedCount] = useState<number | "">("");
  const [reconReport, setReconReport] = useState<ReconciliationReport | null>(null);
  const [reconLoading, setReconLoading] = useState(false);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const conns = await api.listConnectors();
      setConnectors(conns);
      if (conns.length > 0 && !reconConnectorId) {
        setReconConnectorId(conns[0].connector_id);
      }

      const jobList = await api.listIntegrationJobs();
      setJobs(jobList);

      const qual = await api.getQualityAssessment();
      setQuality(qual);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleHealthCheck = async (connectorId: string) => {
    setActionLoading(`health-${connectorId}`);
    try {
      const res = await api.getConnectorHealth(connectorId);
      setHealthMap((prev) => ({ ...prev, [connectorId]: res }));
      setSuccessMsg(`Connector '${connectorId}' health checked: ${res.healthy ? "HEALTHY" : "DEGRADED"}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setActionLoading(null);
    }
  };

  const handleSync = async (connectorId: string) => {
    setActionLoading(`sync-${connectorId}`);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await api.triggerConnectorSync(connectorId, { batch_size: 200, max_batches: 5 });
      setSuccessMsg(
        `Sync completed for '${connectorId}': Accepted ${res.records_accepted}, Duplicates ${res.records_duplicates}, Corrected ${res.records_corrected}`
      );
      // Reload jobs and connectors
      await loadData();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setActionLoading(null);
    }
  };

  const handleToggleState = async (connectorId: string, currentEnabled: boolean) => {
    setActionLoading(`toggle-${connectorId}`);
    setError(null);
    try {
      await api.setConnectorState(connectorId, !currentEnabled);
      setSuccessMsg(`Connector '${connectorId}' is now ${!currentEnabled ? "ENABLED" : "DISABLED"}`);
      await loadData();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setActionLoading(null);
    }
  };

  const handleRunReconciliation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!reconConnectorId) return;
    setReconLoading(true);
    setError(null);
    try {
      const report = await api.runReconciliation({
        connector_id: reconConnectorId,
        expected_source_count: reconExpectedCount === "" ? undefined : Number(reconExpectedCount),
      });
      setReconReport(report);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setReconLoading(false);
    }
  };

  return (
    <div>
      <div className="wb-card">
        <div className="wb-card-header">
          <div>
            <h2 className="wb-card-title">Bank Integration Gateway &amp; Source Connectors</h2>
            <p className="wb-card-subtitle">
              Secure source system adapters &bull; Idempotent batch &amp; event ingestion &bull; Automated reconciliation
            </p>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button className="wb-btn" onClick={loadData} disabled={loading}>
              {loading ? "Refreshing..." : "Refresh"}
            </button>
          </div>
        </div>

        {error && (
          <div className="notice-banner" style={{ borderColor: "var(--accent-rose)", color: "#fca5a5", marginBottom: 12 }}>
            <strong>Integration Error:</strong> {error}
          </div>
        )}

        {successMsg && (
          <div className="notice-banner" style={{ borderColor: "var(--accent-emerald)", color: "#86efac", marginBottom: 12 }}>
            <strong>Status:</strong> {successMsg}
          </div>
        )}

        <div className="wb-tabs-bar" style={{ display: "flex", gap: 8, borderBottom: "1px solid var(--border-color)", paddingBottom: 8 }}>
          <button
            className={`wb-tab ${subTab === "connectors" ? "active" : ""}`}
            onClick={() => setSubTab("connectors")}
          >
            Connectors ({connectors.length})
          </button>
          <button
            className={`wb-tab ${subTab === "jobs" ? "active" : ""}`}
            onClick={() => setSubTab("jobs")}
          >
            Ingestion Jobs ({jobs.length})
          </button>
          <button
            className={`wb-tab ${subTab === "reconciliation" ? "active" : ""}`}
            onClick={() => setSubTab("reconciliation")}
          >
            Reconciliation &amp; Audits
          </button>
          <button
            className={`wb-tab ${subTab === "quality" ? "active" : ""}`}
            onClick={() => setSubTab("quality")}
          >
            Data Quality &amp; Readiness
          </button>
        </div>
      </div>

      {/* Subtab 1: Connectors */}
      {subTab === "connectors" && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))", gap: 16 }}>
          {connectors.map((c) => {
            const health = healthMap[c.connector_id];
            const isSyncing = actionLoading === `sync-${c.connector_id}`;
            const isToggling = actionLoading === `toggle-${c.connector_id}`;
            const isChecking = actionLoading === `health-${c.connector_id}`;

            return (
              <div key={c.connector_id} className="wb-card" style={{ marginBottom: 0 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 8 }}>
                  <div>
                    <h3 style={{ fontSize: 15, color: "var(--accent-blue)", margin: 0, fontFamily: "var(--font-mono)" }}>
                      {c.connector_id}
                    </h3>
                    <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
                      Source: <strong>{c.source_system}</strong> &bull; Type: {c.connector_type}
                    </span>
                  </div>
                  <span className={`chip ${c.enabled ? "chip-approved" : "chip-closed"}`}>
                    {c.enabled ? "ENABLED" : "DISABLED"}
                  </span>
                </div>

                <div style={{ fontSize: 13, color: "var(--text-muted)", margin: "12px 0", lineHeight: 1.6 }}>
                  <div><strong>Ingested Records:</strong> {c.records_ingested.toLocaleString()}</div>
                  <div><strong>Current Cursor:</strong> <code>{c.cursor || "genesis"}</code></div>
                  <div><strong>Version:</strong> {c.version}</div>
                  {health && (
                    <div>
                      <strong>Health:</strong>{" "}
                      <span style={{ color: health.healthy ? "#86efac" : "#fca5a5" }}>
                        {health.healthy ? "✓ Online" : "✗ Unhealthy"}
                      </span>
                    </div>
                  )}
                </div>

                <div style={{ display: "flex", gap: 8, marginTop: 14 }}>
                  <button
                    className="wb-btn"
                    onClick={() => handleSync(c.connector_id)}
                    disabled={!c.enabled || isSyncing}
                    style={{ flex: 1 }}
                  >
                    {isSyncing ? "Syncing..." : "Sync Now"}
                  </button>
                  <button
                    className="wb-btn"
                    onClick={() => handleHealthCheck(c.connector_id)}
                    disabled={isChecking}
                  >
                    {isChecking ? "Checking..." : "Health"}
                  </button>
                  <button
                    className="wb-btn"
                    onClick={() => handleToggleState(c.connector_id, c.enabled)}
                    disabled={isToggling}
                  >
                    {c.enabled ? "Disable" : "Enable"}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Subtab 2: Ingestion Jobs */}
      {subTab === "jobs" && (
        <div className="wb-card">
          <h3 className="wb-card-title" style={{ fontSize: 16, marginBottom: 12 }}>Ingestion Job History</h3>
          {jobs.length === 0 ? (
            <div style={{ color: "var(--text-muted)", padding: 20 }}>No ingestion jobs recorded yet.</div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid var(--border-color)", textAlign: "left", color: "var(--text-muted)" }}>
                    <th style={{ padding: "8px 12px" }}>Job ID</th>
                    <th style={{ padding: "8px 12px" }}>Connector</th>
                    <th style={{ padding: "8px 12px" }}>Status</th>
                    <th style={{ padding: "8px 12px" }}>Accepted</th>
                    <th style={{ padding: "8px 12px" }}>Duplicates</th>
                    <th style={{ padding: "8px 12px" }}>Corrected</th>
                    <th style={{ padding: "8px 12px" }}>Rejected</th>
                    <th style={{ padding: "8px 12px" }}>Started At</th>
                  </tr>
                </thead>
                <tbody>
                  {jobs.map((j) => (
                    <tr key={j.job_id} style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                      <td style={{ padding: "8px 12px", fontFamily: "var(--font-mono)" }}>{j.job_id}</td>
                      <td style={{ padding: "8px 12px" }}>{j.connector_id}</td>
                      <td style={{ padding: "8px 12px" }}>
                        <span className={`chip ${j.status === "completed" ? "chip-approved" : j.status === "failed" ? "chip-closed" : "chip-open"}`}>
                          {j.status.toUpperCase()}
                        </span>
                      </td>
                      <td style={{ padding: "8px 12px" }}>{j.records_accepted}</td>
                      <td style={{ padding: "8px 12px" }}>{j.records_duplicates}</td>
                      <td style={{ padding: "8px 12px" }}>{j.records_corrected}</td>
                      <td style={{ padding: "8px 12px" }}>{j.records_rejected}</td>
                      <td style={{ padding: "8px 12px", color: "var(--text-muted)" }}>
                        {new Date(j.started_at).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Subtab 3: Reconciliation */}
      {subTab === "reconciliation" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          <div className="wb-card">
            <h3 className="wb-card-title" style={{ fontSize: 16, marginBottom: 8 }}>Run Ingestion Reconciliation</h3>
            <p className="wb-card-subtitle" style={{ marginBottom: 16 }}>
              Compare Toroka canonical database counts against bank source-system expectations.
            </p>

            <form onSubmit={handleRunReconciliation}>
              <div style={{ marginBottom: 14 }}>
                <label style={{ display: "block", fontSize: 12, color: "var(--text-muted)", marginBottom: 4 }}>
                  Target Connector
                </label>
                <select
                  value={reconConnectorId}
                  onChange={(e) => setReconConnectorId(e.target.value)}
                  style={{ width: "100%", padding: 8, background: "var(--card-bg)", color: "var(--text-color)", border: "1px solid var(--border-color)", borderRadius: 4 }}
                >
                  {connectors.map((c) => (
                    <option key={c.connector_id} value={c.connector_id}>
                      {c.connector_id} ({c.source_system})
                    </option>
                  ))}
                </select>
              </div>

              <div style={{ marginBottom: 16 }}>
                <label style={{ display: "block", fontSize: 12, color: "var(--text-muted)", marginBottom: 4 }}>
                  Expected Source Record Count
                </label>
                <input
                  type="number"
                  placeholder="e.g. 50000"
                  value={reconExpectedCount}
                  onChange={(e) => setReconExpectedCount(e.target.value === "" ? "" : Number(e.target.value))}
                  style={{ width: "100%", padding: 8, background: "var(--card-bg)", color: "var(--text-color)", border: "1px solid var(--border-color)", borderRadius: 4 }}
                />
              </div>

              <button className="wb-btn" type="submit" disabled={reconLoading || !reconConnectorId}>
                {reconLoading ? "Reconciling..." : "Execute Reconciliation"}
              </button>
            </form>
          </div>

          <div className="wb-card">
            <h3 className="wb-card-title" style={{ fontSize: 16, marginBottom: 8 }}>Reconciliation Report</h3>
            {reconReport ? (
              <div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
                  <span style={{ fontSize: 13, color: "var(--text-muted)" }}>Connector: <strong>{reconReport.connector_id}</strong></span>
                  <span className={`chip ${reconReport.status === "reconciled" ? "chip-approved" : "chip-closed"}`}>
                    {reconReport.status === "reconciled" ? "✓ RECONCILED" : "⚠ DISCREPANCY"}
                  </span>
                </div>

                <div style={{ fontSize: 13, lineHeight: 1.8 }}>
                  <div><strong>Total Ingested Records:</strong> {reconReport.ingested_record_count.toLocaleString()}</div>
                  <div><strong>Versioned Corrections:</strong> {reconReport.corrected_record_count.toLocaleString()}</div>
                  <div><strong>Rejected / Dead-Letter:</strong> {reconReport.rejected_record_count.toLocaleString()}</div>
                  {typeof reconReport.expected_source_count === "number" && (
                    <div><strong>Expected Source Count:</strong> {reconReport.expected_source_count.toLocaleString()}</div>
                  )}
                  <div>
                    <strong>Discrepancy:</strong>{" "}
                    <span style={{ color: reconReport.discrepancy === 0 ? "#86efac" : "#fca5a5" }}>
                      {reconReport.discrepancy}
                    </span>
                  </div>
                </div>

                <div className="notice-banner" style={{ marginTop: 16, fontSize: 12 }}>
                  {reconReport.explanation}
                </div>
              </div>
            ) : (
              <div style={{ color: "var(--text-muted)", padding: "30px 0", textAlign: "center" }}>
                Select a connector and trigger reconciliation to view count audits.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Subtab 4: Quality & Detector Impact */}
      {subTab === "quality" && quality && (
        <div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 16 }}>
            <div className="wb-card" style={{ marginBottom: 0, textAlign: "center" }}>
              <div style={{ fontSize: 24, fontWeight: "bold", color: "var(--accent-blue)" }}>
                {quality.total_records}
              </div>
              <div style={{ fontSize: 12, color: "var(--text-muted)" }}>Total Ingested</div>
            </div>
            <div className="wb-card" style={{ marginBottom: 0, textAlign: "center" }}>
              <div style={{ fontSize: 24, fontWeight: "bold", color: "#86efac" }}>
                {quality.valid_records}
              </div>
              <div style={{ fontSize: 12, color: "var(--text-muted)" }}>Valid Canonical</div>
            </div>
            <div className="wb-card" style={{ marginBottom: 0, textAlign: "center" }}>
              <div style={{ fontSize: 24, fontWeight: "bold", color: "#fca5a5" }}>
                {quality.rejected_records}
              </div>
              <div style={{ fontSize: 12, color: "var(--text-muted)" }}>Rejected Records</div>
            </div>
            <div className="wb-card" style={{ marginBottom: 0, textAlign: "center" }}>
              <div style={{ fontSize: 24, fontWeight: "bold", color: quality.issues_count === 0 ? "#86efac" : "#fbbf24" }}>
                {quality.issues_count}
              </div>
              <div style={{ fontSize: 12, color: "var(--text-muted)" }}>Quality Warnings</div>
            </div>
          </div>

          <div className="wb-card">
            <h3 className="wb-card-title" style={{ fontSize: 16, marginBottom: 12 }}>
              Detector Scenario Impact Matrix
            </h3>
            <p className="wb-card-subtitle" style={{ marginBottom: 16 }}>
              Direct mapping from ingested canonical data quality to insider-risk detector execution modes.
            </p>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 12 }}>
              {quality.detector_impact.map((d) => (
                <div key={d.detector_id} style={{ border: "1px solid var(--border-color)", padding: 12, borderRadius: 6, background: "rgba(255,255,255,0.02)" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                    <strong style={{ fontSize: 14, fontFamily: "var(--font-mono)" }}>{d.detector_id}</strong>
                    <span className={`chip ${d.status === "READY" ? "chip-approved" : d.status === "DEGRADED" ? "chip-open" : "chip-closed"}`}>
                      {d.status}
                    </span>
                  </div>
                  <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 8 }}>
                    {d.explanation}
                  </div>
                  {d.required_missing.length > 0 && (
                    <div style={{ fontSize: 11, color: "#fca5a5" }}>
                      Missing Required: {d.required_missing.join(", ")}
                    </div>
                  )}
                  {d.optional_missing.length > 0 && (
                    <div style={{ fontSize: 11, color: "#fbbf24" }}>
                      Missing Supporting: {d.optional_missing.join(", ")}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
export default IntegrationsView;
