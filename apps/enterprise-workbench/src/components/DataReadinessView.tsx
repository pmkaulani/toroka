import React, { useEffect, useState } from "react";
import { api } from "../api";
import { DataContractResponse } from "../types";

export const DataReadinessView: React.FC = () => {
  const [contract, setContract] = useState<DataContractResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    api
      .getDataContract()
      .then((data) => {
        setContract(data);
        setError(null);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div>
      <div className="wb-card">
        <div className="wb-card-header">
          <div>
            <h2 className="wb-card-title">Bank Data Contract &amp; Detector Readiness</h2>
            <p className="wb-card-subtitle">
              Canonical banking schema specification v{contract?.contract_version || "2.0.0"} &bull; Ingestion readiness
              matrix
            </p>
          </div>
          <span className="chip chip-approved">CONTRACT V{contract?.contract_version || "2.0.0"} ACTIVE</span>
        </div>

        {error && (
          <div className="notice-banner" style={{ borderColor: "var(--accent-rose)", color: "#fca5a5" }}>
            <strong>Contract Load Error:</strong> {error}
          </div>
        )}

        <div className="notice-banner">
          <strong>Data Steward Oversight:</strong> Toroka requires explicit declaration of banking data feeds.
          Missing fields degrade or block individual detector capabilities rather than crashing ingestion.
        </div>
      </div>

      {loading ? (
        <div style={{ color: "var(--text-muted)", padding: 20 }}>Inspecting data contract registry...</div>
      ) : contract ? (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(360px, 1fr))", gap: 16 }}>
          {Object.entries(contract.feeds).map(([feedName, feed]) => (
            <div key={feedName} className="wb-card" style={{ marginBottom: 0 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                <h3 style={{ fontSize: 14, color: "var(--accent-blue)", fontFamily: "var(--font-mono)" }}>
                  {feedName}
                </h3>
                <span className={`chip ${feed.required_feed ? "chip-open" : "chip-closed"}`}>
                  {feed.required_feed ? "MANDATORY FEED" : "SUPPORTING FEED"}
                </span>
              </div>
              <p style={{ fontSize: 11, color: "var(--text-dim)", marginBottom: 12 }}>
                Runtime Storage Key: <span className="code-mono">{feed.runtime_key}</span>
              </p>

              <div className="wb-table-wrapper">
                <table className="wb-table" style={{ fontSize: 12 }}>
                  <thead>
                    <tr>
                      <th>Field Name</th>
                      <th>Requirement</th>
                    </tr>
                  </thead>
                  <tbody>
                    {feed.fields.map((f) => (
                      <tr key={f.name}>
                        <td>
                          <span className="code-mono">{f.name}</span>
                        </td>
                        <td>
                          <span
                            className={`chip ${
                              f.required_for_ingestion ? "chip-open" : "chip-closed"
                            }`}
                            style={{ fontSize: 10 }}
                          >
                            {f.required_for_ingestion ? "REQUIRED" : "OPTIONAL"}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
};
