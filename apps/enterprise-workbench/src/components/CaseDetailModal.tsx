import React, { useEffect, useState } from "react";
import { api, getCurrentPersona } from "../api";
import { CaseDetail, CaseNote, ClosureProposal, RevealRequest } from "../types";

interface CaseDetailModalProps {
  caseId: string;
  onClose: () => void;
  onConsumeReveal: (pseudonym: string, plaintext: string, consumedAt: string) => void;
}

export const CaseDetailModal: React.FC<CaseDetailModalProps> = ({
  caseId,
  onClose,
  onConsumeReveal,
}) => {
  const persona = getCurrentPersona();
  const [caseData, setCaseData] = useState<CaseDetail | null>(null);
  const [notes, setNotes] = useState<CaseNote[]>([]);
  const [proposals, setProposals] = useState<ClosureProposal[]>([]);
  const [reveals, setReveals] = useState<RevealRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Forms
  const [newNote, setNewNote] = useState("");
  const [revealPseudonym, setRevealPseudonym] = useState("");
  const [revealReason, setRevealReason] = useState("");
  const [revealTtl, setRevealTtl] = useState(24);

  const [closureDisposition, setClosureDisposition] = useState("substantiated_referral");
  const [closureNote, setClosureNote] = useState("");
  const [closureAlternatives, setClosureAlternatives] = useState("");
  const [reviewNote, setReviewNote] = useState("");

  const refreshCase = async () => {
    try {
      const [c, n, p, r] = await Promise.all([
        api.getCase(caseId),
        api.listCaseNotes(caseId),
        api.listCaseClosureProposals(caseId),
        api.listPendingReveals().catch(() => [] as RevealRequest[]),
      ]);
      setCaseData(c);
      setNotes(n);
      setProposals(p);
      setReveals(r.filter((req) => req.case_id === caseId));

      // Extract pseudonyms from focus
      if (!revealPseudonym && c.focus) {
        setRevealPseudonym(c.focus);
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  useEffect(() => {
    setLoading(true);
    refreshCase().finally(() => setLoading(false));
  }, [caseId, persona.id]);

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNote.trim()) return;
    setActionError(null);
    try {
      await api.addCaseNote(caseId, newNote.trim());
      setNewNote("");
      setActionSuccess("Case note appended to immutable record.");
      await refreshCase();
    } catch (err: any) {
      setActionError(err.message);
    }
  };

  const handleRequestReveal = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!revealPseudonym.trim() || !revealReason.trim()) return;
    setActionError(null);
    try {
      await api.createRevealRequest(caseId, {
        pseudonym: revealPseudonym.trim(),
        reason: revealReason.trim(),
        ttl_hours: Number(revealTtl),
      });
      setRevealReason("");
      setActionSuccess("Identity reveal request submitted for authoriser dual-approval.");
      await refreshCase();
    } catch (err: any) {
      setActionError(err.message);
    }
  };

  const handleConsumeReveal = async (requestId: string) => {
    setActionError(null);
    try {
      const res = await api.consumeReveal(requestId);
      onConsumeReveal(res.pseudonym, res.plaintext_identity, res.consumed_at);
      await refreshCase();
    } catch (err: any) {
      setActionError(err.message);
    }
  };

  const handleProposeClosure = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!caseData) return;
    setActionError(null);
    try {
      await api.proposeClosure(caseId, {
        disposition: closureDisposition,
        closing_note: closureNote.trim(),
        alternatives_considered: closureAlternatives.trim(),
        expected_case_version: caseData.version,
      });
      setClosureNote("");
      setClosureAlternatives("");
      setActionSuccess("Case closure proposed. Pending independent authoriser review.");
      await refreshCase();
    } catch (err: any) {
      setActionError(err.message);
    }
  };

  const handleReviewClosure = async (proposalId: string, approve: boolean) => {
    setActionError(null);
    try {
      await api.reviewClosureProposal(proposalId, {
        approve,
        review_note: reviewNote.trim() || undefined,
      });
      setReviewNote("");
      setActionSuccess(approve ? "Case closure approved and executed." : "Closure proposal rejected. Case remains open.");
      await refreshCase();
    } catch (err: any) {
      setActionError(err.message);
    }
  };

  if (loading) {
    return (
      <div className="modal-overlay">
        <div className="modal-box" style={{ padding: 40, textAlign: "center" }}>
          Loading case investigation record...
        </div>
      </div>
    );
  }

  if (error || !caseData) {
    return (
      <div className="modal-overlay">
        <div className="modal-box" style={{ padding: 30 }}>
          <div className="notice-banner" style={{ borderColor: "var(--accent-rose)", color: "#fca5a5" }}>
            <strong>Error:</strong> {error || "Case could not be loaded."}
          </div>
          <button className="wb-btn wb-btn-subtle" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    );
  }

  const isClosed = caseData.status === "closed";
  const pieces = caseData.snapshot?.pieces || [];
  const pendingProposal = proposals.find((p) => p.status === "pending");

  return (
    <div className="modal-overlay">
      <div className="modal-box">
        {/* Header */}
        <div className="modal-header">
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span className={`chip chip-${caseData.status}`}>{caseData.status}</span>
              <span className={`chip ${caseData.label.includes("PRIORITY") ? "chip-priority" : "chip-review"}`}>
                {caseData.label}
              </span>
              <h2 className="modal-title">{caseData.focus}</h2>
              <span className="code-mono">v{caseData.version}</span>
            </div>
            <p style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
              Case ID: <span className="code-mono">{caseData.id}</span> &bull; Installation:{" "}
              <span className="code-mono">{caseData.installation_id}</span>
            </p>
          </div>
          <button
            onClick={onClose}
            style={{
              background: "transparent",
              border: "none",
              color: "var(--text-muted)",
              cursor: "pointer",
              fontSize: 20,
            }}
          >
            ✕
          </button>
        </div>

        {/* Body */}
        <div className="modal-body">
          {actionError && (
            <div className="notice-banner" style={{ borderColor: "var(--accent-rose)", color: "#fca5a5" }}>
              <strong>Operation Blocked:</strong> {actionError}
            </div>
          )}

          {actionSuccess && (
            <div className="notice-banner" style={{ borderColor: "var(--accent-emerald)", color: "#6ee7b7" }}>
              <strong>Success:</strong> {actionSuccess}
            </div>
          )}

          {/* Closed Case Banner */}
          {isClosed && (
            <div
              className="wb-card"
              style={{
                backgroundColor: "rgba(15, 23, 42, 0.9)",
                borderColor: "var(--border-strong)",
                borderLeft: "4px solid var(--accent-blue)",
              }}
            >
              <h3 style={{ fontSize: 14, color: "var(--accent-blue)", marginBottom: 6 }}>
                🔒 Closed Investigation Record
              </h3>
              <p style={{ fontSize: 12, color: "var(--text-main)" }}>
                <strong>Disposition:</strong> <span className="chip chip-closed">{caseData.disposition}</span>
              </p>
              <p style={{ fontSize: 12, marginTop: 4 }}>
                <strong>Closing Note:</strong> {caseData.closing_note}
              </p>
              {caseData.alternatives_considered && (
                <p style={{ fontSize: 12, marginTop: 4, color: "var(--text-muted)" }}>
                  <strong>Alternative Explanations Considered:</strong> {caseData.alternatives_considered}
                </p>
              )}
              <p style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 6 }}>
                Closed on {caseData.closed_at ? new Date(caseData.closed_at).toLocaleString() : "N/A"}
              </p>
            </div>
          )}

          {/* Section 1: Provenance & Evidence Engine Snapshot */}
          <div className="wb-card">
            <div className="wb-card-header">
              <h3 className="wb-card-title">Provenance &amp; Cryptographic Evidence Snapshot</h3>
              <span className="chip chip-approved">INTEGRITY VERIFIED</span>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, fontSize: 12, marginBottom: 12 }}>
              <div>
                <span style={{ color: "var(--text-muted)" }}>Snapshot SHA-256 Digest:</span>
                <div className="code-mono" style={{ wordBreak: "break-all", marginTop: 2 }}>
                  {caseData.snapshot_sha256}
                </div>
              </div>
              <div>
                <span style={{ color: "var(--text-muted)" }}>Run Manifest Reference:</span>
                <div className="code-mono" style={{ marginTop: 2 }}>
                  {caseData.manifest_id || "Direct Intake"}
                </div>
              </div>
            </div>

            <h4 style={{ fontSize: 13, color: "var(--text-main)", marginBottom: 8, marginTop: 16 }}>
              Pieces of Evaluated Evidence ({pieces.length})
            </h4>

            {pieces.length === 0 ? (
              <p style={{ color: "var(--text-muted)", fontSize: 12 }}>No structured evidence pieces attached.</p>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {pieces.map((piece, idx) => (
                  <div
                    key={idx}
                    style={{
                      backgroundColor: "var(--bg-surface)",
                      border: "1px solid var(--border-subtle)",
                      borderRadius: 6,
                      padding: "10px 12px",
                      fontSize: 12,
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                      <strong style={{ color: "var(--accent-blue)" }}>{piece.provider}</strong>
                      <span className="code-mono" style={{ color: "var(--accent-amber)" }}>
                        +{piece.risk_points} pts
                      </span>
                    </div>
                    <p style={{ color: "var(--text-main)" }}>{piece.summary}</p>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Section 2: Append-Only Notes */}
          <div className="wb-card">
            <div className="wb-card-header">
              <h3 className="wb-card-title">Append-Only Investigation Notes ({notes.length})</h3>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: 8, marginBottom: 16 }}>
              {notes.length === 0 ? (
                <p style={{ color: "var(--text-muted)", fontSize: 12 }}>No notes recorded for this case yet.</p>
              ) : (
                notes.map((n) => (
                  <div
                    key={n.id}
                    style={{
                      backgroundColor: "var(--bg-surface)",
                      border: "1px solid var(--border-subtle)",
                      borderRadius: 6,
                      padding: "10px 12px",
                      fontSize: 12,
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", color: "var(--text-muted)", fontSize: 11, marginBottom: 4 }}>
                      <span>Author: <strong style={{ color: "var(--text-main)" }}>{n.author_subject}</strong></span>
                      <span>{new Date(n.created_at).toLocaleString()}</span>
                    </div>
                    <p style={{ color: "var(--text-main)", whiteSpace: "pre-wrap" }}>{n.body}</p>
                  </div>
                ))
              )}
            </div>

            {!isClosed && (
              <form onSubmit={handleAddNote}>
                <textarea
                  rows={2}
                  placeholder="Record factual observations, source findings, or investigative context..."
                  value={newNote}
                  onChange={(e) => setNewNote(e.target.value)}
                  style={{
                    width: "100%",
                    backgroundColor: "var(--bg-surface)",
                    color: "var(--text-main)",
                    border: "1px solid var(--border-subtle)",
                    borderRadius: 6,
                    padding: "8px 12px",
                    fontSize: 13,
                    outline: "none",
                    marginBottom: 8,
                  }}
                />
                <button type="submit" className="wb-btn wb-btn-primary" disabled={!newNote.trim()}>
                  Append Immutable Note
                </button>
              </form>
            )}
          </div>

          {/* Section 3: Identity Reveal Workflow */}
          <div className="wb-card">
            <div className="wb-card-header">
              <h3 className="wb-card-title">Protected Identity Vault &amp; Reveal Requests</h3>
              <span className="code-mono" style={{ fontSize: 11 }}>SEPARATE VAULT BOUNDARY</span>
            </div>

            {reveals.length > 0 && (
              <div style={{ marginBottom: 16 }}>
                <h4 style={{ fontSize: 12, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 8 }}>
                  Active Reveal Authorizations
                </h4>
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {reveals.map((r) => (
                    <div
                      key={r.id}
                      style={{
                        backgroundColor: "var(--bg-surface)",
                        border: "1px solid var(--border-subtle)",
                        borderRadius: 6,
                        padding: "10px 12px",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                      }}
                    >
                      <div>
                        <span className="code-mono" style={{ color: "var(--accent-amber)" }}>
                          {r.pseudonym}
                        </span>
                        <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
                          Reason: {r.reason} &bull; Requested by {r.requested_by}
                        </div>
                      </div>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <span className={`chip chip-${r.status}`}>{r.status}</span>
                        {r.status === "approved" && (
                          <button
                            className="wb-btn wb-btn-success"
                            onClick={() => handleConsumeReveal(r.id)}
                          >
                            Consume &amp; Reveal Identity Once
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {!isClosed && (
              <form onSubmit={handleRequestReveal} style={{ marginBottom: 16 }}>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 8 }}>
                  <div>
                    <label style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase" }}>
                      Target Pseudonym
                    </label>
                    <input
                      type="text"
                      value={revealPseudonym}
                      onChange={(e) => setRevealPseudonym(e.target.value)}
                      placeholder="e.g. staff:S1024"
                      style={{
                        width: "100%",
                        backgroundColor: "var(--bg-surface)",
                        color: "var(--text-main)",
                        border: "1px solid var(--border-subtle)",
                        borderRadius: 6,
                        padding: "6px 10px",
                        fontSize: 12,
                        marginTop: 4,
                      }}
                    />
                  </div>
                  <div>
                    <label style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase" }}>
                      Authorization Window (TTL)
                    </label>
                    <select
                      value={revealTtl}
                      onChange={(e) => setRevealTtl(Number(e.target.value))}
                      style={{
                        width: "100%",
                        backgroundColor: "var(--bg-surface)",
                        color: "var(--text-main)",
                        border: "1px solid var(--border-subtle)",
                        borderRadius: 6,
                        padding: "6px 10px",
                        fontSize: 12,
                        marginTop: 4,
                      }}
                    >
                      <option value={12}>12 Hours</option>
                      <option value={24}>24 Hours (Standard)</option>
                      <option value={48}>48 Hours</option>
                    </select>
                  </div>
                </div>

                <div style={{ marginBottom: 8 }}>
                  <label style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase" }}>
                    Substantive Justification (Mandatory &bull; min 10 chars)
                  </label>
                  <input
                    type="text"
                    value={revealReason}
                    onChange={(e) => setRevealReason(e.target.value)}
                    placeholder="Document factual justification why unmasking is necessary..."
                    style={{
                      width: "100%",
                      backgroundColor: "var(--bg-surface)",
                      color: "var(--text-main)",
                      border: "1px solid var(--border-subtle)",
                      borderRadius: 6,
                      padding: "6px 10px",
                      fontSize: 12,
                      marginTop: 4,
                    }}
                  />
                </div>

                <button
                  type="submit"
                  className="wb-btn wb-btn-subtle"
                  disabled={!revealPseudonym.trim() || revealReason.trim().length < 10}
                >
                  Submit Identity Reveal Request
                </button>
              </form>
            )}
          </div>

          {/* Section 4: Maker-Checker Case Closure */}
          {!isClosed && (
            <div className="wb-card">
              <div className="wb-card-header">
                <h3 className="wb-card-title">Maker-Checker Case Closure Governance</h3>
                <span className="code-mono">DUAL APPROVAL REQUIRED</span>
              </div>

              {pendingProposal ? (
                <div
                  style={{
                    backgroundColor: "rgba(245, 158, 11, 0.1)",
                    border: "1px solid var(--accent-amber)",
                    borderRadius: 6,
                    padding: 14,
                    marginBottom: 16,
                  }}
                >
                  <h4 style={{ color: "var(--accent-amber)", fontSize: 13, marginBottom: 6 }}>
                    Pending Closure Recommendation
                  </h4>
                  <p style={{ fontSize: 12 }}>
                    <strong>Proposed Disposition:</strong>{" "}
                    <span className="chip chip-closed">{pendingProposal.disposition}</span>
                  </p>
                  <p style={{ fontSize: 12, marginTop: 4 }}>
                    <strong>Recommended by:</strong> {pendingProposal.requested_by} at{" "}
                    {new Date(pendingProposal.requested_at).toLocaleString()}
                  </p>
                  <p style={{ fontSize: 12, marginTop: 4 }}>
                    <strong>Closing Note:</strong> {pendingProposal.closing_note}
                  </p>
                  {pendingProposal.alternatives_considered && (
                    <p style={{ fontSize: 12, marginTop: 4, color: "var(--text-muted)" }}>
                      <strong>Alternative Explanations:</strong> {pendingProposal.alternatives_considered}
                    </p>
                  )}

                  {/* Authoriser Review Actions */}
                  {persona.role === "authoriser" ? (
                    <div style={{ marginTop: 14, borderTop: "1px solid rgba(245, 158, 11, 0.3)", paddingTop: 12 }}>
                      {pendingProposal.requested_by === persona.id ? (
                        <div style={{ color: "var(--accent-rose)", fontSize: 12 }}>
                          🚫 <strong>Maker-Checker Guard:</strong> You proposed this closure. Under bank governance, you
                          cannot approve your own recommendation. An independent authoriser must review it.
                        </div>
                      ) : (
                        <div>
                          <input
                            type="text"
                            placeholder="Optional authoriser review comment..."
                            value={reviewNote}
                            onChange={(e) => setReviewNote(e.target.value)}
                            style={{
                              width: "100%",
                              backgroundColor: "var(--bg-surface)",
                              color: "var(--text-main)",
                              border: "1px solid var(--border-subtle)",
                              borderRadius: 6,
                              padding: "6px 10px",
                              fontSize: 12,
                              marginBottom: 8,
                            }}
                          />
                          <div style={{ display: "flex", gap: 10 }}>
                            <button
                              className="wb-btn wb-btn-success"
                              onClick={() => handleReviewClosure(pendingProposal.id, true)}
                            >
                              Approve Case Closure
                            </button>
                            <button
                              className="wb-btn wb-btn-danger"
                              onClick={() => handleReviewClosure(pendingProposal.id, false)}
                            >
                              Reject Closure Recommendation
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  ) : (
                    <p style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 8 }}>
                      Awaiting compliance authoriser review.
                    </p>
                  )}
                </div>
              ) : (
                <form onSubmit={handleProposeClosure}>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: 10, marginBottom: 10 }}>
                    <div>
                      <label style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase" }}>
                        Proposed Disposition (Mandatory)
                      </label>
                      <select
                        value={closureDisposition}
                        onChange={(e) => setClosureDisposition(e.target.value)}
                        style={{
                          width: "100%",
                          backgroundColor: "var(--bg-surface)",
                          color: "var(--text-main)",
                          border: "1px solid var(--border-subtle)",
                          borderRadius: 6,
                          padding: "6px 10px",
                          fontSize: 12,
                          marginTop: 4,
                        }}
                      >
                        <option value="substantiated_referral">Substantiated — Disciplinary / Regulatory Referral</option>
                        <option value="not_substantiated">Not Substantiated — Legitimate Business Justification</option>
                        <option value="data_gap_or_control_weakness">Data Gap / Control Weakness Identified</option>
                      </select>
                    </div>

                    <div>
                      <label style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase" }}>
                        Factual Closing Summary (Mandatory)
                      </label>
                      <textarea
                        rows={2}
                        value={closureNote}
                        onChange={(e) => setClosureNote(e.target.value)}
                        placeholder="Detail the conclusive investigative findings..."
                        style={{
                          width: "100%",
                          backgroundColor: "var(--bg-surface)",
                          color: "var(--text-main)",
                          border: "1px solid var(--border-subtle)",
                          borderRadius: 6,
                          padding: "6px 10px",
                          fontSize: 12,
                          marginTop: 4,
                        }}
                      />
                    </div>

                    <div>
                      <label style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase" }}>
                        Alternative Explanations Considered (Mandatory)
                      </label>
                      <textarea
                        rows={2}
                        value={closureAlternatives}
                        onChange={(e) => setClosureAlternatives(e.target.value)}
                        placeholder="Document alternative hypotheses examined and ruled out..."
                        style={{
                          width: "100%",
                          backgroundColor: "var(--bg-surface)",
                          color: "var(--text-main)",
                          border: "1px solid var(--border-subtle)",
                          borderRadius: 6,
                          padding: "6px 10px",
                          fontSize: 12,
                          marginTop: 4,
                        }}
                      />
                    </div>
                  </div>

                  <button
                    type="submit"
                    className="wb-btn wb-btn-primary"
                    disabled={!closureNote.trim() || !closureAlternatives.trim()}
                  >
                    Submit Closure Recommendation for Dual Approval
                  </button>
                </form>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="modal-footer">
          <button className="wb-btn wb-btn-subtle" onClick={onClose}>
            Close Inspection
          </button>
        </div>
      </div>
    </div>
  );
};
