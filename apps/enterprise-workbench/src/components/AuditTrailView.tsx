import React, { useEffect, useState } from "react";
import { api } from "../api";
import { AuditTimelineItem, AuditVerification } from "../types";

export const AuditTrailView: React.FC = () => {
  const [verification, setVerification] = useState<AuditVerification | null>(null);
  const [records, setRecords] = useState<AuditTimelineItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchRecords = async () => {
    setLoading(true);
    try {
      const [v, r] = await Promise.all([
        api.verifyAuditChain(),
        api.listAuditRecords(),
      ]);
      setVerification(v);
      setRecords(r);
      setError(null);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRecords();
  }, []);

  const handleVerifyNow = async () => {
    setVerifying(true);
    try {
      const res = await api.verifyAuditChain();
      setVerification(res);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div>
      <div className="wb-card">
        <div className="wb-card-header">
          <div>
            <h2 className="wb-card-title">Cryptographic Audit Chain &amp; Compliance Trail</h2>
            <p className="wb-card-subtitle">
              SHA-256 hash-linked immutable ledger of all case operations, reveals, and governance actions
            </p>
          </div>
          <button
            className="wb-btn wb-btn-primary"
            onClick={handleVerifyNow}
            disabled={verifying}
          >
            {verifying ? "Verifying Hash Chain..." : "Verify Hash Chain Now"}
          </button>
        </div>

        {error && (
          <div className="notice-banner" style={{ borderColor: "var(--accent-rose)", color: "#fca5a5" }}>
            <strong>Audit Access Restriction:</strong> {error}
          </div>
        )}

        {verification && (
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
              gap: 16,
              marginTop: 12,
            }}
          >
            <div className="kpi-card highlight-emerald">
              <div className="kpi-label">Chain Integrity</div>
              <div className="kpi-value" style={{ fontSize: 20, color: verification.valid ? "#10b981" : "#f43f5e" }}>
                {verification.valid ? "✓ CRYPTOGRAPHICALLY VALID" : "✗ CHAIN BROKEN"}
              </div>
              <div className="kpi-meta">Genesis to Head verification</div>
            </div>

            <div className="kpi-card highlight-blue">
              <div className="kpi-label">Verified Record Count</div>
              <div className="kpi-value">{verification.records_verified}</div>
              <div className="kpi-meta">Consecutive linked events</div>
            </div>

            <div className="kpi-card" style={{ gridColumn: "span 2" }}>
              <div className="kpi-label">Current Head Hash (Merkle Link)</div>
              <div className="code-mono" style={{ marginTop: 8, wordBreak: "break-all", fontSize: 13 }}>
                {verification.head_hash}
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="wb-card">
        <h3 className="wb-card-title" style={{ marginBottom: 16 }}>
          Immutable Event Ledger ({records.length} Events)
        </h3>

        {loading ? (
          <div style={{ color: "var(--text-muted)", padding: 20 }}>Inspecting audit ledger...</div>
        ) : records.length === 0 ? (
          <p style={{ color: "var(--text-muted)", padding: 20 }}>No audit events recorded.</p>
        ) : (
          <div className="wb-table-wrapper">
            <table className="wb-table">
              <thead>
                <tr>
                  <th>Seq #</th>
                  <th>Timestamp</th>
                  <th>Action</th>
                  <th>Actor Subject</th>
                  <th>Role</th>
                  <th>Target Type</th>
                  <th>Target ID</th>
                  <th>Safe Metadata Digest</th>
                </tr>
              </thead>
              <tbody>
                {records.map((r) => (
                  <tr key={r.sequence}>
                    <td>
                      <span className="code-mono">#{r.sequence}</span>
                    </td>
                    <td style={{ color: "var(--text-muted)", fontSize: 12 }}>
                      {new Date(r.created_at).toLocaleString()}
                    </td>
                    <td>
                      <strong style={{ color: "var(--accent-blue)" }}>{r.action}</strong>
                    </td>
                    <td>
                      <strong>{r.actor_subject}</strong>
                    </td>
                    <td>
                      <span className="chip chip-closed" style={{ fontSize: 10 }}>
                        {r.actor_role}
                      </span>
                    </td>
                    <td>{r.target_type}</td>
                    <td>
                      <span className="code-mono" style={{ fontSize: 11 }}>
                        {r.target_id || "—"}
                      </span>
                    </td>
                    <td style={{ maxWidth: 300, fontSize: 11 }}>
                      <pre style={{ margin: 0, whiteSpace: "pre-wrap", color: "var(--text-dim)" }}>
                        {JSON.stringify(r.safe_metadata)}
                      </pre>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
