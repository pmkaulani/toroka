import React, { useEffect, useState } from "react";
import { api, getCurrentPersona } from "../api";
import { CaseSummary } from "../types";

interface MyCasesViewProps {
  onSelectCase: (caseId: string) => void;
}

export const MyCasesView: React.FC<MyCasesViewProps> = ({ onSelectCase }) => {
  const persona = getCurrentPersona();
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchCases = () => {
    setLoading(true);
    const filter = statusFilter === "all" ? undefined : statusFilter;
    api
      .listCases(filter)
      .then((data) => {
        setCases(data.items);
        setTotal(data.total);
        setError(null);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchCases();
  }, [persona.id, statusFilter]);

  const filtered = cases.filter((c) => {
    if (!search.trim()) return true;
    const term = search.toLowerCase();
    return (
      c.id.toLowerCase().includes(term) ||
      c.label.toLowerCase().includes(term) ||
      c.focus.toLowerCase().includes(term)
    );
  });

  return (
    <div className="wb-card">
      <div className="wb-card-header">
        <div>
          <h2 className="wb-card-title">My Assigned Investigations ({total})</h2>
          <p className="wb-card-subtitle">Active insider-risk cases assigned to {persona.name}</p>
        </div>

        <div style={{ display: "flex", gap: 12 }}>
          <input
            type="text"
            placeholder="Search by focus or label..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{
              backgroundColor: "var(--bg-surface)",
              color: "var(--text-main)",
              border: "1px solid var(--border-subtle)",
              borderRadius: 6,
              padding: "6px 12px",
              fontSize: 13,
              outline: "none",
            }}
          />

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            style={{
              backgroundColor: "var(--bg-surface)",
              color: "var(--text-main)",
              border: "1px solid var(--border-subtle)",
              borderRadius: 6,
              padding: "6px 10px",
              fontSize: 13,
              outline: "none",
            }}
          >
            <option value="all">All Statuses</option>
            <option value="open">Open</option>
            <option value="closed">Closed</option>
          </select>
        </div>
      </div>

      {loading ? (
        <div style={{ color: "var(--text-muted)", padding: 20 }}>Loading assigned cases...</div>
      ) : error ? (
        <div className="notice-banner" style={{ borderColor: "var(--accent-rose)", color: "#fca5a5" }}>
          <strong>Access Denied:</strong> {error}
        </div>
      ) : filtered.length === 0 ? (
        <div style={{ padding: 40, textAlign: "center", color: "var(--text-muted)" }}>
          No cases match the selected filter.
        </div>
      ) : (
        <div className="wb-table-wrapper">
          <table className="wb-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Priority / Label</th>
                <th>Target Focus</th>
                <th>Case Identifier</th>
                <th>Version</th>
                <th>Created</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((c) => (
                <tr key={c.id}>
                  <td>
                    <span className={`chip chip-${c.status}`}>{c.status}</span>
                  </td>
                  <td>
                    <span
                      className={`chip ${
                        c.label.includes("PRIORITY") ? "chip-priority" : "chip-review"
                      }`}
                    >
                      {c.label}
                    </span>
                  </td>
                  <td>
                    <strong style={{ fontFamily: "var(--font-mono)", color: "var(--text-main)" }}>
                      {c.focus}
                    </strong>
                  </td>
                  <td>
                    <span className="code-mono">{c.id}</span>
                  </td>
                  <td>v{c.version}</td>
                  <td style={{ color: "var(--text-muted)", fontSize: 12 }}>
                    {new Date(c.created_at).toLocaleString()}
                  </td>
                  <td>
                    <button
                      className="wb-btn wb-btn-subtle"
                      onClick={() => onSelectCase(c.id)}
                    >
                      Inspect Evidence &amp; Notes
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
