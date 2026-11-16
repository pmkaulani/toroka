import React, { useState, useEffect } from "react";
import { api } from "../api";
import {
  CopilotThread,
  CopilotMessage,
  CopilotReportDraft,
  CopilotStatus,
  CaseSummary,
  Persona,
} from "../types";

interface CopilotViewProps {
  currentPersona: Persona;
  selectedCaseId?: string | null;
  onSelectCase?: (caseId: string) => void;
}

export const CopilotView: React.FC<CopilotViewProps> = ({
  currentPersona,
  selectedCaseId,
  onSelectCase,
}) => {
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [activeCaseId, setActiveCaseId] = useState<string>(selectedCaseId || "");
  const [threads, setThreads] = useState<CopilotThread[]>([]);
  const [activeThreadId, setActiveThreadId] = useState<string>("");
  const [messages, setMessages] = useState<CopilotMessage[]>([]);
  const [promptInput, setPromptInput] = useState<string>("");
  const [isSending, setIsSending] = useState<boolean>(false);
  const [statusInfo, setStatusInfo] = useState<CopilotStatus | null>(null);

  // Active view tab: "chat" or "reports"
  const [viewMode, setViewMode] = useState<"chat" | "reports">("chat");

  // Reports
  const [reports, setReports] = useState<CopilotReportDraft[]>([]);
  const [activeReport, setActiveReport] = useState<CopilotReportDraft | null>(null);
  const [reportEditText, setReportEditText] = useState<string>("");
  const [reviewNotes, setReviewNotes] = useState<string>("");
  const [isGeneratingReport, setIsGeneratingReport] = useState<boolean>(false);

  // Citation modal
  const [selectedCitation, setSelectedCitation] = useState<{
    evidenceId: string;
    quotedText: string;
  } | null>(null);

  const [notification, setNotification] = useState<string | null>(null);

  // 1. Load cases and copilot status on mount
  useEffect(() => {
    api.getCopilotStatus()
      .then(setStatusInfo)
      .catch((err) => console.error("Failed to load Copilot status", err));

    api.listCases()
      .then((res) => {
        setCases(res.items || []);
        if (!activeCaseId && res.items?.length > 0) {
          setActiveCaseId(res.items[0].id);
        }
      })
      .catch((err) => console.error("Failed to list cases", err));
  }, []);

  // Update activeCaseId if parent passes a new selectedCaseId
  useEffect(() => {
    if (selectedCaseId && selectedCaseId !== activeCaseId) {
      setActiveCaseId(selectedCaseId);
    }
  }, [selectedCaseId]);

  // 2. Load threads and reports when activeCaseId changes
  useEffect(() => {
    if (!activeCaseId) return;

    api.listCopilotThreads(activeCaseId)
      .then((res) => {
        setThreads(res);
        if (res.length > 0) {
          setActiveThreadId(res[0].thread_id);
        } else {
          // Auto-create initial thread if none exist
          api.createCopilotThread(activeCaseId, "Investigation Copilot Thread")
            .then((newTh) => {
              setThreads([newTh]);
              setActiveThreadId(newTh.thread_id);
            })
            .catch((e) => console.error("Error creating default thread", e));
        }
      })
      .catch((err) => console.error("Failed to load threads", err));

    api.listReportDrafts(activeCaseId)
      .then((repList) => {
        setReports(repList);
        if (repList.length > 0) {
          setActiveReport(repList[0]);
          setReportEditText(repList[0].investigator_edits_markdown || repList[0].content_markdown);
        } else {
          setActiveReport(null);
          setReportEditText("");
        }
      })
      .catch((err) => console.error("Failed to load reports", err));
  }, [activeCaseId]);

  // 3. Load messages when activeThreadId changes
  useEffect(() => {
    if (!activeThreadId) {
      setMessages([]);
      return;
    }

    api.listCopilotMessages(activeThreadId)
      .then(setMessages)
      .catch((err) => console.error("Failed to load messages", err));
  }, [activeThreadId]);

  const handleCreateThread = async () => {
    if (!activeCaseId) return;
    try {
      const th = await api.createCopilotThread(activeCaseId, `Investigation ${new Date().toLocaleTimeString()}`);
      setThreads([th, ...threads]);
      setActiveThreadId(th.thread_id);
      showNotice("New investigation thread created.");
    } catch (e) {
      console.error(e);
      showNotice("Failed to create thread.");
    }
  };

  const handleSendMessage = async (textToSend?: string) => {
    const query = textToSend || promptInput;
    if (!query.trim() || !activeThreadId || isSending) return;

    setIsSending(true);
    setPromptInput("");

    // Optimistic user message
    const tempUserMsg: CopilotMessage = {
      message_id: `temp_${Date.now()}`,
      thread_id: activeThreadId,
      installation_id: "",
      case_id: activeCaseId,
      role: "user",
      content: query,
      claims: [],
      citations: [],
      tool_calls: [],
      created_at: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, tempUserMsg]);

    try {
      const resp = await api.sendCopilotMessage(activeThreadId, query);
      setMessages((prev) => [...prev.filter((m) => m.message_id !== tempUserMsg.message_id), tempUserMsg, resp]);
    } catch (err) {
      console.error("Copilot turn failed", err);
      showNotice("Copilot investigation query failed.");
    } finally {
      setIsSending(false);
    }
  };

  const handleGenerateReport = async (reportType: string = "INVESTIGATION_SUMMARY") => {
    if (!activeCaseId) return;
    setIsGeneratingReport(true);
    try {
      const draft = await api.generateReportDraft({
        case_id: activeCaseId,
        thread_id: activeThreadId || undefined,
        report_type: reportType,
        title: `${reportType.replace(/_/g, " ")}: Case ${activeCaseId.substring(0, 8)}`,
      });
      setReports([draft, ...reports]);
      setActiveReport(draft);
      setReportEditText(draft.content_markdown);
      setViewMode("reports");
      showNotice("AI Report draft generated from verified evidence.");
    } catch (e) {
      console.error(e);
      showNotice("Failed to generate report draft.");
    } finally {
      setIsGeneratingReport(false);
    }
  };

  const handleSaveReportEdits = async () => {
    if (!activeReport) return;
    try {
      const updated = await api.updateReportDraft(activeReport.draft_id, reportEditText);
      setActiveReport(updated);
      setReports(reports.map((r) => (r.draft_id === updated.draft_id ? updated : r)));
      showNotice("Investigator edits saved (Status: INVESTIGATOR_REVIEW).");
    } catch (e) {
      console.error(e);
      showNotice("Failed to save report edits.");
    }
  };

  const handleReviewReport = async (decision: "ACCEPTED" | "REJECTED") => {
    if (!activeReport) return;
    try {
      const reviewed = await api.reviewReportDraft(activeReport.draft_id, decision, reviewNotes);
      setActiveReport(reviewed);
      setReports(reports.map((r) => (r.draft_id === reviewed.draft_id ? reviewed : r)));
      setReviewNotes("");
      showNotice(`Report draft was successfully ${decision}.`);
    } catch (e) {
      console.error(e);
      showNotice(`Failed to ${decision.toLowerCase()} report.`);
    }
  };

  const handleFeedback = async (messageId: string, rating: number) => {
    try {
      await api.submitCopilotFeedback(messageId, rating);
      showNotice("Investigator feedback recorded for audit and quality tracking.");
    } catch (e) {
      console.error(e);
    }
  };

  const showNotice = (msg: string) => {
    setNotification(msg);
    setTimeout(() => setNotification(null), 4000);
  };

  const activeCase = cases.find((c) => c.id === activeCaseId);

  return (
    <div className="copilot-workspace" style={{ display: "flex", flexDirection: "column", gap: "16px", padding: "16px" }}>
      {/* Top Bar: Case Context & Status */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", background: "#fff", border: "1px solid #e2e8f0", borderRadius: "8px", padding: "12px 16px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
          <div>
            <label style={{ fontSize: "11px", fontWeight: 700, color: "#64748b", textTransform: "uppercase" }}>Investigated Case</label>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginTop: "4px" }}>
              <select
                value={activeCaseId}
                onChange={(e) => {
                  setActiveCaseId(e.target.value);
                  if (onSelectCase) onSelectCase(e.target.value);
                }}
                style={{ padding: "6px 12px", borderRadius: "6px", border: "1px solid #cbd5e1", fontSize: "14px", fontWeight: 600 }}
              >
                {cases.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.label} ({c.id.substring(0, 8)}) - {c.status}
                  </option>
                ))}
              </select>
              {activeCase && (
                <span style={{ fontSize: "12px", background: "#f1f5f9", padding: "4px 8px", borderRadius: "4px", color: "#334155" }}>
                  Focus: <strong>{activeCase.focus}</strong>
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Status Pill */}
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          {statusInfo && (
            <div style={{ fontSize: "12px", display: "flex", alignItems: "center", gap: "6px", background: "#f0fdf4", color: "#166534", padding: "6px 12px", borderRadius: "20px", border: "1px solid #bbf7d0" }}>
              <span style={{ width: "8px", height: "8px", borderRadius: "50%", background: "#22c55e" }}></span>
              <span><strong>{statusInfo.model}</strong> ({statusInfo.air_gapped ? "Air-Gapped Bank Host" : "Cloud Host"})</span>
            </div>
          )}

          {/* Mode Switcher */}
          <div style={{ display: "flex", background: "#e2e8f0", padding: "2px", borderRadius: "6px" }}>
            <button
              onClick={() => setViewMode("chat")}
              style={{
                padding: "6px 14px",
                border: "none",
                borderRadius: "4px",
                fontSize: "13px",
                fontWeight: 600,
                cursor: "pointer",
                background: viewMode === "chat" ? "#fff" : "transparent",
                color: viewMode === "chat" ? "#0f172a" : "#64748b",
              }}
            >
              Investigation Q&A
            </button>
            <button
              onClick={() => setViewMode("reports")}
              style={{
                padding: "6px 14px",
                border: "none",
                borderRadius: "4px",
                fontSize: "13px",
                fontWeight: 600,
                cursor: "pointer",
                background: viewMode === "reports" ? "#fff" : "transparent",
                color: viewMode === "reports" ? "#0f172a" : "#64748b",
              }}
            >
              Report Drafting ({reports.length})
            </button>
          </div>
        </div>
      </div>

      {notification && (
        <div style={{ background: "#eff6ff", color: "#1d4ed8", padding: "8px 16px", borderRadius: "6px", fontSize: "13px", border: "1px solid #bfdbfe" }}>
          {notification}
        </div>
      )}

      {/* Main Mode 1: Investigation Q&A */}
      {viewMode === "chat" && (
        <div style={{ display: "grid", gridTemplateColumns: "260px 1fr", gap: "16px", minHeight: "560px" }}>
          {/* Threads Column */}
          <div style={{ background: "#fff", border: "1px solid #e2e8f0", borderRadius: "8px", padding: "12px", display: "flex", flexDirection: "column", gap: "12px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span style={{ fontSize: "12px", fontWeight: 700, color: "#64748b", textTransform: "uppercase" }}>Threads</span>
              <button
                onClick={handleCreateThread}
                style={{ background: "#0284c7", color: "#fff", border: "none", borderRadius: "4px", padding: "4px 8px", fontSize: "11px", fontWeight: 600, cursor: "pointer" }}
              >
                + New Thread
              </button>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: "6px", overflowY: "auto" }}>
              {threads.map((th) => (
                <div
                  key={th.thread_id}
                  onClick={() => setActiveThreadId(th.thread_id)}
                  style={{
                    padding: "8px 10px",
                    borderRadius: "6px",
                    cursor: "pointer",
                    fontSize: "13px",
                    background: activeThreadId === th.thread_id ? "#f1f5f9" : "transparent",
                    borderLeft: activeThreadId === th.thread_id ? "3px solid #0284c7" : "3px solid transparent",
                  }}
                >
                  <div style={{ fontWeight: activeThreadId === th.thread_id ? 700 : 500, color: "#0f172a" }}>{th.title}</div>
                  <div style={{ fontSize: "11px", color: "#94a3b8", marginTop: "2px" }}>
                    {new Date(th.updated_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Conversation & Action Column */}
          <div style={{ background: "#fff", border: "1px solid #e2e8f0", borderRadius: "8px", display: "flex", flexDirection: "column", height: "650px" }}>
            {/* Prompt Shortcuts */}
            <div style={{ padding: "10px 16px", borderBottom: "1px solid #f1f5f9", display: "flex", gap: "8px", overflowX: "auto" }}>
              <button
                onClick={() => handleSendMessage("Explain what happened in this case. Start from the earliest relevant activity.")}
                style={{ whiteSpace: "nowrap", padding: "4px 10px", borderRadius: "14px", border: "1px solid #cbd5e1", background: "#f8fafc", fontSize: "12px", color: "#334155", cursor: "pointer" }}
              >
                Explain Case
              </button>
              <button
                onClick={() => handleSendMessage("Explain the timeline of events and relationships.")}
                style={{ whiteSpace: "nowrap", padding: "4px 10px", borderRadius: "14px", border: "1px solid #cbd5e1", background: "#f8fafc", fontSize: "12px", color: "#334155", cursor: "pointer" }}
              >
                Explain Timeline
              </button>
              <button
                onClick={() => handleSendMessage("Examine network connections, beneficiaries, and related accounts.")}
                style={{ whiteSpace: "nowrap", padding: "4px 10px", borderRadius: "14px", border: "1px solid #cbd5e1", background: "#f8fafc", fontSize: "12px", color: "#334155", cursor: "pointer" }}
              >
                Investigate Network
              </button>
              <button
                onClick={() => handleSendMessage("Have we seen similar historical cases before in institutional memory?")}
                style={{ whiteSpace: "nowrap", padding: "4px 10px", borderRadius: "14px", border: "1px solid #cbd5e1", background: "#f8fafc", fontSize: "12px", color: "#334155", cursor: "pointer" }}
              >
                Compare Historical Cases
              </button>
              <button
                onClick={() => handleSendMessage("What are the highest-value outstanding evidence gaps?")}
                style={{ whiteSpace: "nowrap", padding: "4px 10px", borderRadius: "14px", border: "1px solid #cbd5e1", background: "#f8fafc", fontSize: "12px", color: "#334155", cursor: "pointer" }}
              >
                Identify Missing Evidence
              </button>
              <button
                onClick={() => handleGenerateReport("INVESTIGATION_SUMMARY")}
                style={{ whiteSpace: "nowrap", padding: "4px 10px", borderRadius: "14px", border: "1px solid #cbd5e1", background: "#f8fafc", fontSize: "12px", color: "#0284c7", fontWeight: 600, cursor: "pointer" }}
              >
                Draft Report
              </button>
            </div>

            {/* Messages Scroll Area */}
            <div style={{ flex: 1, padding: "16px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "16px" }}>
              {messages.length === 0 && (
                <div style={{ color: "#94a3b8", textAlign: "center", marginTop: "100px", fontSize: "14px" }}>
                  Ask Toroka Copilot to examine evidence, review timelines, explain connected entities, or draft reports.
                </div>
              )}

              {messages.map((m) => (
                <div key={m.message_id} style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                  {/* Sender Banner */}
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "12px", color: m.role === "user" ? "#0284c7" : "#0f172a", fontWeight: 700 }}>
                    <span>{m.role === "user" ? "Investigator" : "Toroka Investigation Copilot"}</span>
                    <span style={{ fontWeight: 400, color: "#94a3b8", fontSize: "11px" }}>
                      {new Date(m.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                    </span>
                    {m.grounding_report && (
                      <span style={{ fontSize: "10px", padding: "2px 6px", borderRadius: "10px", background: m.grounding_report.valid ? "#dcfce7" : "#fee2e2", color: m.grounding_report.valid ? "#166534" : "#991b1b" }}>
                        Grounding Verified ({m.grounding_report.verified_claims} claims)
                      </span>
                    )}
                  </div>

                  {/* Main Bubble */}
                  <div
                    style={{
                      background: m.role === "user" ? "#f1f5f9" : "#ffffff",
                      border: "1px solid",
                      borderColor: m.role === "user" ? "#e2e8f0" : "#cbd5e1",
                      borderRadius: "8px",
                      padding: "12px 16px",
                      fontSize: "14px",
                      color: "#1e293b",
                      lineHeight: "1.5",
                    }}
                  >
                    <div>{m.content}</div>

                    {/* Claims Breakdown */}
                    {m.claims && m.claims.length > 0 && (
                      <div style={{ marginTop: "12px", display: "flex", flexDirection: "column", gap: "8px" }}>
                        <div style={{ fontSize: "11px", fontWeight: 700, color: "#64748b", textTransform: "uppercase" }}>Evidence-Grounded Breakdown</div>
                        {m.claims.map((c) => (
                          <div
                            key={c.claim_id}
                            style={{
                              padding: "8px 12px",
                              borderRadius: "6px",
                              background: "#f8fafc",
                              borderLeft: `4px solid ${
                                c.kind === "fact" ? "#22c55e" : c.kind === "inference" ? "#f59e0b" : c.kind === "unknown" ? "#94a3b8" : "#3b82f6"
                              }`,
                              fontSize: "13px",
                            }}
                          >
                            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
                              <span
                                style={{
                                  fontSize: "10px",
                                  fontWeight: 800,
                                  textTransform: "uppercase",
                                  padding: "2px 6px",
                                  borderRadius: "4px",
                                  background: c.kind === "fact" ? "#dcfce7" : c.kind === "inference" ? "#fef3c7" : c.kind === "unknown" ? "#f1f5f9" : "#dbeafe",
                                  color: c.kind === "fact" ? "#166534" : c.kind === "inference" ? "#92400e" : c.kind === "unknown" ? "#475569" : "#1e40af",
                                }}
                              >
                                {c.kind}
                              </span>
                              <span>{c.statement}</span>
                            </div>

                            {/* Citations / Quotes */}
                            {c.quotes && c.quotes.length > 0 && (
                              <div style={{ marginTop: "4px", display: "flex", gap: "6px", flexWrap: "wrap" }}>
                                {c.quotes.map((q, idx) => (
                                  <button
                                    key={idx}
                                    onClick={() => setSelectedCitation({ evidenceId: q.evidence_id, quotedText: q.quoted_text })}
                                    style={{
                                      fontSize: "11px",
                                      background: "#e0f2fe",
                                      color: "#0369a1",
                                      border: "1px solid #bae6fd",
                                      borderRadius: "4px",
                                      padding: "2px 6px",
                                      cursor: "pointer",
                                    }}
                                  >
                                    Cite: {q.evidence_id}
                                  </button>
                                ))}
                              </div>
                            )}

                            {/* Limitations */}
                            {c.limitations && (
                              <div style={{ fontSize: "11px", color: "#b45309", marginTop: "4px" }}>
                                <em>Limitation:</em> {c.limitations}
                              </div>
                            )}

                            {/* Investigative Basis */}
                            {c.investigative_basis && (
                              <div style={{ fontSize: "11px", color: "#1d4ed8", marginTop: "4px" }}>
                                <em>Investigative Basis:</em> {c.investigative_basis}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Feedback Buttons */}
                    {m.role === "assistant" && (
                      <div style={{ display: "flex", justifyContent: "flex-end", gap: "8px", marginTop: "8px" }}>
                        <button
                          onClick={() => handleFeedback(m.message_id, 1)}
                          style={{ background: "none", border: "none", cursor: "pointer", fontSize: "12px", color: "#64748b" }}
                          title="Verified & helpful"
                        >
                          👍 Helpful
                        </button>
                        <button
                          onClick={() => handleFeedback(m.message_id, -1)}
                          style={{ background: "none", border: "none", cursor: "pointer", fontSize: "12px", color: "#64748b" }}
                          title="Incorrect or incomplete"
                        >
                          👎 Needs correction
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              ))}

              {isSending && (
                <div style={{ color: "#0284c7", fontSize: "13px", fontStyle: "italic" }}>
                  Toroka is evaluating case evidence and validating citations...
                </div>
              )}
            </div>

            {/* Input Bar */}
            <div style={{ padding: "12px 16px", borderTop: "1px solid #e2e8f0", display: "flex", gap: "8px" }}>
              <input
                type="text"
                value={promptInput}
                onChange={(e) => setPromptInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleSendMessage();
                }}
                placeholder="Ask about this case (e.g. What happened? What evidence is missing?)..."
                disabled={isSending}
                style={{ flex: 1, padding: "8px 12px", borderRadius: "6px", border: "1px solid #cbd5e1", fontSize: "14px" }}
              />
              <button
                onClick={() => handleSendMessage()}
                disabled={isSending || !promptInput.trim()}
                style={{
                  background: isSending || !promptInput.trim() ? "#cbd5e1" : "#0284c7",
                  color: "#fff",
                  border: "none",
                  borderRadius: "6px",
                  padding: "8px 16px",
                  fontWeight: 600,
                  cursor: isSending || !promptInput.trim() ? "not-allowed" : "pointer",
                }}
              >
                Send
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Main Mode 2: Report Drafting & Governance */}
      {viewMode === "reports" && (
        <div style={{ display: "grid", gridTemplateColumns: "280px 1fr", gap: "16px", minHeight: "560px" }}>
          {/* Drafts List Column */}
          <div style={{ background: "#fff", border: "1px solid #e2e8f0", borderRadius: "8px", padding: "12px", display: "flex", flexDirection: "column", gap: "12px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span style={{ fontSize: "12px", fontWeight: 700, color: "#64748b", textTransform: "uppercase" }}>Draft Reports</span>
              <button
                onClick={() => handleGenerateReport("INVESTIGATION_SUMMARY")}
                disabled={isGeneratingReport}
                style={{ background: "#0284c7", color: "#fff", border: "none", borderRadius: "4px", padding: "4px 8px", fontSize: "11px", fontWeight: 600, cursor: "pointer" }}
              >
                {isGeneratingReport ? "Drafting..." : "+ New Draft"}
              </button>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: "8px", overflowY: "auto" }}>
              {reports.length === 0 && <div style={{ fontSize: "12px", color: "#94a3b8" }}>No reports generated yet.</div>}
              {reports.map((r) => (
                <div
                  key={r.draft_id}
                  onClick={() => {
                    setActiveReport(r);
                    setReportEditText(r.investigator_edits_markdown || r.content_markdown);
                  }}
                  style={{
                    padding: "8px 10px",
                    borderRadius: "6px",
                    cursor: "pointer",
                    fontSize: "13px",
                    background: activeReport?.draft_id === r.draft_id ? "#f1f5f9" : "transparent",
                    borderLeft: activeReport?.draft_id === r.draft_id ? "3px solid #0284c7" : "3px solid transparent",
                  }}
                >
                  <div style={{ fontWeight: 600, color: "#0f172a" }}>{r.title}</div>
                  <div style={{ display: "flex", justifyContent: "space-between", marginTop: "4px", alignItems: "center" }}>
                    <span
                      style={{
                        fontSize: "10px",
                        fontWeight: 700,
                        padding: "2px 6px",
                        borderRadius: "4px",
                        background:
                          r.status === "ACCEPTED"
                            ? "#dcfce7"
                            : r.status === "REJECTED"
                            ? "#fee2e2"
                            : r.status === "INVESTIGATOR_REVIEW"
                            ? "#fef3c7"
                            : "#f1f5f9",
                        color:
                          r.status === "ACCEPTED"
                            ? "#166534"
                            : r.status === "REJECTED"
                            ? "#991b1b"
                            : r.status === "INVESTIGATOR_REVIEW"
                            ? "#92400e"
                            : "#475569",
                      }}
                    >
                      {r.status}
                    </span>
                    <span style={{ fontSize: "11px", color: "#94a3b8" }}>
                      {new Date(r.created_at).toLocaleDateString()}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Draft Editor & Review Panel */}
          {activeReport ? (
            <div style={{ background: "#fff", border: "1px solid #e2e8f0", borderRadius: "8px", padding: "16px", display: "flex", flexDirection: "column", gap: "16px" }}>
              {/* Draft Header */}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid #e2e8f0", paddingBottom: "12px" }}>
                <div>
                  <h3 style={{ margin: 0, fontSize: "16px", fontWeight: 700, color: "#0f172a" }}>{activeReport.title}</h3>
                  <div style={{ fontSize: "12px", color: "#64748b", marginTop: "4px" }}>
                    Evidence Context Hash: <code>{activeReport.evidence_context_hash.substring(0, 16)}...</code> | Status: <strong>{activeReport.status}</strong>
                  </div>
                </div>

                <div style={{ display: "flex", gap: "8px" }}>
                  <button
                    onClick={handleSaveReportEdits}
                    style={{ background: "#0284c7", color: "#fff", border: "none", borderRadius: "6px", padding: "6px 12px", fontWeight: 600, fontSize: "12px", cursor: "pointer" }}
                  >
                    Save Investigator Edits
                  </button>
                </div>
              </div>

              {/* Editor Area */}
              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                <label style={{ fontSize: "12px", fontWeight: 700, color: "#475569" }}>
                  Report Markdown (Investigator Editable):
                </label>
                <textarea
                  value={reportEditText}
                  onChange={(e) => setReportEditText(e.target.value)}
                  rows={15}
                  style={{
                    width: "100%",
                    padding: "12px",
                    fontFamily: "monospace",
                    fontSize: "13px",
                    borderRadius: "6px",
                    border: "1px solid #cbd5e1",
                    lineHeight: "1.4",
                  }}
                />
              </div>

              {/* Review Governance Actions */}
              {(currentPersona.role === "authoriser" || currentPersona.role === "investigator" || currentPersona.role === "system_administrator") && (
                <div style={{ background: "#f8fafc", border: "1px solid #e2e8f0", borderRadius: "6px", padding: "12px", display: "flex", flexDirection: "column", gap: "8px" }}>
                  <div style={{ fontSize: "12px", fontWeight: 700, color: "#334155" }}>
                    Human Maker-Checker Review Decision
                  </div>
                  <input
                    type="text"
                    value={reviewNotes}
                    onChange={(e) => setReviewNotes(e.target.value)}
                    placeholder="Enter review notes and rationale..."
                    style={{ padding: "6px 10px", borderRadius: "4px", border: "1px solid #cbd5e1", fontSize: "13px" }}
                  />
                  <div style={{ display: "flex", gap: "8px", justifyContent: "flex-end" }}>
                    <button
                      onClick={() => handleReviewReport("REJECTED")}
                      style={{ background: "#fee2e2", color: "#991b1b", border: "1px solid #fecaca", borderRadius: "4px", padding: "6px 14px", fontWeight: 700, fontSize: "12px", cursor: "pointer" }}
                    >
                      Reject Report
                    </button>
                    <button
                      onClick={() => handleReviewReport("ACCEPTED")}
                      style={{ background: "#166534", color: "#fff", border: "none", borderRadius: "4px", padding: "6px 14px", fontWeight: 700, fontSize: "12px", cursor: "pointer" }}
                    >
                      Accept Report
                    </button>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div style={{ background: "#fff", border: "1px solid #e2e8f0", borderRadius: "8px", padding: "32px", textAlign: "center", color: "#94a3b8" }}>
              Select a report draft or generate a new draft from case evidence.
            </div>
          )}
        </div>
      )}

      {/* Citation Inspector Modal */}
      {selectedCitation && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: "rgba(15, 23, 42, 0.5)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000,
          }}
          onClick={() => setSelectedCitation(null)}
        >
          <div
            style={{
              background: "#fff",
              borderRadius: "8px",
              padding: "20px",
              maxWidth: "500px",
              width: "90%",
              boxShadow: "0 20px 25px -5px rgba(0, 0, 0, 0.1)",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <h4 style={{ margin: "0 0 10px 0", fontSize: "15px", color: "#0f172a" }}>
              Evidence Citation: {selectedCitation.evidenceId}
            </h4>
            <div style={{ fontSize: "12px", color: "#64748b", marginBottom: "8px" }}>
              Exact verified excerpt from banking record:
            </div>
            <div
              style={{
                background: "#f1f5f9",
                border: "1px solid #e2e8f0",
                borderRadius: "6px",
                padding: "12px",
                fontSize: "13px",
                color: "#1e293b",
                fontFamily: "monospace",
                lineHeight: "1.5",
              }}
            >
              "{selectedCitation.quotedText}"
            </div>
            <div style={{ marginTop: "16px", display: "flex", justifyContent: "flex-end" }}>
              <button
                onClick={() => setSelectedCitation(null)}
                style={{ background: "#0284c7", color: "#fff", border: "none", borderRadius: "4px", padding: "6px 14px", fontWeight: 600, cursor: "pointer" }}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
export default CopilotView;
