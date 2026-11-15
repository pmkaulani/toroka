import React, { useEffect, useState } from "react";
import { api, getCurrentPersona } from "../api";
import { ClosureProposal, RevealRequest } from "../types";

export const ReviewQueuesView: React.FC = () => {
  const persona = getCurrentPersona();
  const [closures, setClosures] = useState<ClosureProposal[]>([]);
  const [reveals, setReveals] = useState<RevealRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionMsg, setActionMsg] = useState<string | null>(null);
  const [rejectionNotes, setRejectionNotes] = useState<Record<string, string>>({});

  const refreshQueues = async () => {
    setLoading(true);
    try {
      const [c, r] = await Promise.all([
        api.listPendingClosureProposals(),
        api.listPendingReveals(),
      ]);
      setClosures(c);
      setReveals(r);
      setError(null);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refreshQueues();
  }, [persona.id]);

  const handleApproveClosure = async (proposalId: string) => {
    try {
      await api.reviewClosureProposal(proposalId, { approve: true, review_note: "Authoriser approval confirmed." });
      setActionMsg("Case closure approved.");
      await refreshQueues();
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleRejectClosure = async (proposalId: string) => {
    const note = rejectionNotes[proposalId] || "Closure rejected by authoriser.";
    try {
      await api.reviewClosureProposal(proposalId, { approve: false, review_note: note });
      setActionMsg("Closure recommendation rejected. Case left open.");
      await refreshQueues();
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleApproveReveal = async (requestId: string) => {
    try {
      await api.approveReveal(requestId);
      setActionMsg("Identity reveal approved.");
      await refreshQueues();
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleRejectReveal = async (requestId: string) => {
    const reason = rejectionNotes[requestId] || "Insufficient factual basis for identity unmasking.";
    try {
      await api.rejectReveal(requestId, reason);
      setActionMsg("Identity reveal request rejected.");
      await refreshQueues();
    } catch (err: any) {
      setError(err.message);
    }
  };

  return (
    <div>
      <div className="wb-card">
        <div className="wb-card-header">
          <div>
            <h2 className="wb-card-title">Governance Review Queues</h2>
            <p className="wb-card-subtitle">
              Dual-Approval Verification for Identity Unmasking and Investigation Closure
            </p>
          </div>
          <button className="wb-btn wb-btn-subtle" onClick={refreshQueues}>
            Refresh Queues
          </button>
        </div>

        {error && (
          <div className="notice-banner" style={{ borderColor: "var(--accent-rose)", color: "#fca5a5" }}>
            <strong>Access / Policy Error:</strong> {error}
          </div>
        )}

        {actionMsg && (
          <div className="notice-banner" style={{ borderColor: "var(--accent-emerald)", color: "#6ee7b7" }}>
            {actionMsg}
          </div>
        )}

        <div className="notice-banner">
          <strong>Maker-Checker Policy:</strong> Authorisers are strictly prevented from approving their own
          identity reveal requests or case closure recommendations. All approvals are cryptographically signed into the
          audit hash chain.
        </div>
      </div>

      {/* Queue 1: Pending Case Closures */}
      <div className="wb-card">
        <h3 className="wb-card-title" style={{ marginBottom: 12 }}>
          Pending Case Closure Recommendations ({closures.length})
        </h3>

        {loading ? (
          <div style={{ color: "var(--text-muted)", padding: 12 }}>Loading queue...</div>
        ) : closures.length === 0 ? (
          <p style={{ color: "var(--text-muted)", padding: 12 }}>No pending case closures awaiting review.</p>
        ) : (
          <div className="wb-table-wrapper">
            <table className="wb-table">
              <thead>
                <tr>
                  <th>Case Reference</th>
                  <th>Recommended Disposition</th>
                  <th>Requester</th>
                  <th>Factual Summary</th>
                  <th>Alternatives Considered</th>
                  <th>Version</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {closures.map((p) => {
                  const isRequester = p.requested_by === persona.id;
                  return (
                    <tr key={p.id}>
                      <td>
                        <span className="code-mono">{p.case_id}</span>
                      </td>
                      <td>
                        <span className="chip chip-closed">{p.disposition}</span>
                      </td>
                      <td>
                        <strong>{p.requested_by}</strong>
                        <div style={{ fontSize: 11, color: "var(--text-dim)" }}>
                          {new Date(p.requested_at).toLocaleString()}
                        </div>
                      </td>
                      <td style={{ maxWidth: 220, fontSize: 12 }}>{p.closing_note}</td>
                      <td style={{ maxWidth: 200, fontSize: 12, color: "var(--text-muted)" }}>
                        {p.alternatives_considered || "None documented"}
                      </td>
                      <td>v{p.expected_case_version}</td>
                      <td>
                        {isRequester ? (
                          <span
                            className="chip chip-rejected"
                            title="Dual-approval blocked: an investigator cannot approve their own case closure"
                          >
                            SELF-APPROVAL BLOCKED
                          </span>
                        ) : (
                          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                            <input
                              type="text"
                              placeholder="Review comment..."
                              value={rejectionNotes[p.id] || ""}
                              onChange={(e) =>
                                setRejectionNotes({ ...rejectionNotes, [p.id]: e.target.value })
                              }
                              style={{
                                backgroundColor: "var(--bg-surface)",
                                color: "var(--text-main)",
                                border: "1px solid var(--border-subtle)",
                                borderRadius: 4,
                                padding: "4px 8px",
                                fontSize: 11,
                              }}
                            />
                            <div style={{ display: "flex", gap: 6 }}>
                              <button
                                className="wb-btn wb-btn-success"
                                style={{ padding: "4px 8px", fontSize: 11 }}
                                onClick={() => handleApproveClosure(p.id)}
                              >
                                Approve Closure
                              </button>
                              <button
                                className="wb-btn wb-btn-danger"
                                style={{ padding: "4px 8px", fontSize: 11 }}
                                onClick={() => handleRejectClosure(p.id)}
                              >
                                Reject
                              </button>
                            </div>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Queue 2: Pending Identity Reveals */}
      <div className="wb-card">
        <h3 className="wb-card-title" style={{ marginBottom: 12 }}>
          Pending Identity Reveal Requests ({reveals.length})
        </h3>

        {loading ? (
          <div style={{ color: "var(--text-muted)", padding: 12 }}>Loading queue...</div>
        ) : reveals.length === 0 ? (
          <p style={{ color: "var(--text-muted)", padding: 12 }}>No pending identity reveal requests.</p>
        ) : (
          <div className="wb-table-wrapper">
            <table className="wb-table">
              <thead>
                <tr>
                  <th>Request ID</th>
                  <th>Pseudonym Target</th>
                  <th>Investigator Requester</th>
                  <th>Factual Reason</th>
                  <th>Expires</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {reveals.map((r) => {
                  const isRequester = r.requested_by === persona.id;
                  return (
                    <tr key={r.id}>
                      <td>
                        <span className="code-mono" style={{ fontSize: 11 }}>
                          {r.id.slice(0, 8)}...
                        </span>
                      </td>
                      <td>
                        <strong style={{ fontFamily: "var(--font-mono)", color: "var(--accent-amber)" }}>
                          {r.pseudonym}
                        </strong>
                      </td>
                      <td>
                        <strong>{r.requested_by}</strong>
                        <div style={{ fontSize: 11, color: "var(--text-dim)" }}>
                          {new Date(r.created_at).toLocaleString()}
                        </div>
                      </td>
                      <td style={{ maxWidth: 280, fontSize: 12 }}>{r.reason}</td>
                      <td style={{ fontSize: 11, color: "var(--text-muted)" }}>
                        {new Date(r.expires_at).toLocaleString()}
                      </td>
                      <td>
                        {isRequester ? (
                          <span className="chip chip-rejected">SELF-APPROVAL BLOCKED</span>
                        ) : (
                          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                            <input
                              type="text"
                              placeholder="Rejection reason if denying..."
                              value={rejectionNotes[r.id] || ""}
                              onChange={(e) =>
                                setRejectionNotes({ ...rejectionNotes, [r.id]: e.target.value })
                              }
                              style={{
                                backgroundColor: "var(--bg-surface)",
                                color: "var(--text-main)",
                                border: "1px solid var(--border-subtle)",
                                borderRadius: 4,
                                padding: "4px 8px",
                                fontSize: 11,
                              }}
                            />
                            <div style={{ display: "flex", gap: 6 }}>
                              <button
                                className="wb-btn wb-btn-success"
                                style={{ padding: "4px 8px", fontSize: 11 }}
                                onClick={() => handleApproveReveal(r.id)}
                              >
                                Approve Unmasking
                              </button>
                              <button
                                className="wb-btn wb-btn-danger"
                                style={{ padding: "4px 8px", fontSize: 11 }}
                                onClick={() => handleRejectReveal(r.id)}
                              >
                                Deny
                              </button>
                            </div>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
