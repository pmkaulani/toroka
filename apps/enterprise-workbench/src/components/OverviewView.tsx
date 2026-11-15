import React, { useEffect, useState } from "react";
import { api, getCurrentPersona } from "../api";
import { WorkbenchOverview } from "../types";

interface OverviewViewProps {
  onNavigateTab: (tab: string) => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({ onNavigateTab }) => {
  const persona = getCurrentPersona();
  const [overview, setOverview] = useState<WorkbenchOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    setLoading(true);
    api
      .getOverview()
      .then((data) => {
        if (mounted) {
          setOverview(data);
          setError(null);
        }
      })
      .catch((err) => {
        if (mounted) setError(err.message);
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });
    return () => {
      mounted = false;
    };
  }, [persona.id]);

  if (loading) {
    return <div style={{ color: "var(--text-muted)", padding: 20 }}>Loading operational metrics...</div>;
  }

  if (error) {
    return (
      <div className="notice-banner" style={{ borderColor: "var(--accent-rose)", color: "#fca5a5" }}>
        <strong>Access Error:</strong> {error}
      </div>
    );
  }

  const isDataSteward = persona.role === "data_steward";
  const isInvestigator = persona.role === "investigator";
  const isAuthoriser = persona.role === "authoriser";
  const isAuditor = persona.role === "auditor";

  return (
    <div>
      <div className="wb-card">
        <div className="wb-card-header">
          <div>
            <h2 className="wb-card-title">
              Operational Workspace — {persona.name} ({persona.badge})
            </h2>
            <p className="wb-card-subtitle">
              Role: <strong style={{ color: "var(--accent-blue)" }}>{persona.role}</strong> &bull; Bank Identity ID:{" "}
              <span className="code-mono">{persona.id}</span>
            </p>
          </div>
          <div>
            {isInvestigator && (
              <button className="wb-btn wb-btn-primary" onClick={() => onNavigateTab("my-cases")}>
                View My Assigned Cases
              </button>
            )}
            {isAuthoriser && (
              <button className="wb-btn wb-btn-primary" onClick={() => onNavigateTab("review-queues")}>
                Open Review Queues ({overview?.pending_closures_count || 0})
              </button>
            )}
            {isDataSteward && (
              <button className="wb-btn wb-btn-primary" onClick={() => onNavigateTab("data-readiness")}>
                Inspect Bank Data Contract v2.0.0
              </button>
            )}
            {isAuditor && (
              <button className="wb-btn wb-btn-primary" onClick={() => onNavigateTab("audit-trail")}>
                Verify Audit Hash Chain
              </button>
            )}
          </div>
        </div>

        {isDataSteward ? (
          <div className="notice-banner">
            <strong>Data Stewardship Boundary:</strong> Data Stewards manage feed completeness, ingestion quality, and
            detector readiness mappings. Casework records, identity reveal requests, and case notes are strictly
            segregated and inaccessible under bank policy.
          </div>
        ) : (
          <div className="notice-banner">
            <strong>Maker-Checker Governance Notice:</strong> All identity reveals and case closures require dual
            independent approval. Investigators cannot self-approve reveals or closures. Plaintext identities are never
            persisted in casework records.
          </div>
        )}
      </div>

      <div className="kpi-grid">
        {!isDataSteward && (
          <>
            <div className="kpi-card highlight-blue">
              <div className="kpi-label">My Assigned Cases</div>
              <div className="kpi-value">{overview?.assigned_cases_count ?? 0}</div>
              <div className="kpi-meta">Active assignments for {persona.id}</div>
            </div>

            <div className="kpi-card highlight-indigo">
              <div className="kpi-label">Open Cases</div>
              <div className="kpi-value">{overview?.open_cases_count ?? 0}</div>
              <div className="kpi-meta">Installation total open investigations</div>
            </div>

            <div className="kpi-card highlight-amber">
              <div className="kpi-label">Pending Closures</div>
              <div className="kpi-value">{overview?.pending_closures_count ?? 0}</div>
              <div className="kpi-meta">Maker-checker approval queue</div>
            </div>

            <div className="kpi-card highlight-rose">
              <div className="kpi-label">Pending Reveals</div>
              <div className="kpi-value">{overview?.pending_reveals_count ?? 0}</div>
              <div className="kpi-meta">Identity vault access requests</div>
            </div>
          </>
        )}

        <div className="kpi-card highlight-emerald">
          <div className="kpi-label">Data Contract</div>
          <div className="kpi-value" style={{ fontSize: 22, paddingTop: 4 }}>
            v{overview?.contract_version ?? "2.0.0"}
          </div>
          <div className="kpi-meta">Standard Bank Schema Spec</div>
        </div>

        <div className="kpi-card">
          <div className="kpi-label">Audit Log Chain</div>
          <div className="kpi-value">{overview?.audit_records_count ?? 0}</div>
          <div className="kpi-meta">Tamper-evident recorded events</div>
        </div>
      </div>
    </div>
  );
};
