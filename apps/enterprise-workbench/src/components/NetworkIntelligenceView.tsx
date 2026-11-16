import React, { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import {
  CaseSummary,
  EntityLinkCandidate,
  EvidenceSubgraph,
  FindingEvidenceSubgraph,
  NetworkEdge,
  NetworkNode,
  NetworkPatternFinding,
  Persona,
  ShortestPathResult,
} from "../types";

interface Props {
  currentPersona: Persona;
  selectedCaseId?: string | null;
  onSelectCase?: (caseId: string) => void;
  onNavigateTab?: (tab: string) => void;
}

export const NetworkIntelligenceView: React.FC<Props> = ({
  currentPersona,
  selectedCaseId,
  onSelectCase,
  onNavigateTab,
}) => {
  const [subTab, setSubTab] = useState<
    "explorer" | "transactions" | "case_network" | "findings" | "entity_links"
  >("explorer");

  // Core State
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [activeCaseId, setActiveCaseId] = useState<string>(selectedCaseId || "");
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  // Explorer State
  const [searchEntity, setSearchEntity] = useState<string>("account:acc_mule_target");
  const [expandDepth, setExpandDepth] = useState<number>(2);
  const [includeWeak, setIncludeWeak] = useState<boolean>(false);
  const [entityTypeFilter, setEntityTypeFilter] = useState<string>("all");
  const [relTypeFilter, setRelTypeFilter] = useState<string>("all");

  // Active Subgraph
  const [subgraph, setSubgraph] = useState<EvidenceSubgraph | null>(null);
  const [selectedNode, setSelectedNode] = useState<NetworkNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<NetworkEdge | null>(null);

  // Shortest Path State
  const [pathSource, setPathSource] = useState<string>("");
  const [pathTarget, setPathTarget] = useState<string>("");
  const [pathResult, setPathResult] = useState<ShortestPathResult | null>(null);
  const [findingPath, setFindingPath] = useState<boolean>(false);

  // Findings State
  const [findings, setFindings] = useState<NetworkPatternFinding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<NetworkPatternFinding | null>(null);
  const [findingEvidence, setFindingEvidence] = useState<FindingEvidenceSubgraph | null>(null);
  const [loadingEvidence, setLoadingEvidence] = useState<boolean>(false);

  // Entity Links State
  const [candidates, setCandidates] = useState<EntityLinkCandidate[]>([]);
  const [selectedCandidate, setSelectedCandidate] = useState<EntityLinkCandidate | null>(null);
  const [reviewDecision, setReviewDecision] = useState<string>("SAME_ENTITY_CONFIRMED");
  const [reviewRationale, setReviewRationale] = useState<string>("");
  const [submittingReview, setSubmittingReview] = useState<boolean>(false);

  // Graph Visualization Canvas State
  const [zoom, setZoom] = useState<number>(1);
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [draggingNode, setDraggingNode] = useState<string | null>(null);
  const [nodePositions, setNodePositions] = useState<Record<string, { x: number; y: number }>>({});
  const svgRef = useRef<SVGSVGElement | null>(null);

  // Permissions
  const canReview = ["authoriser", "investigator", "system_administrator"].includes(
    currentPersona.role
  );

  // Initial Load
  useEffect(() => {
    loadCases();
    loadFindings();
    loadCandidates();
    // Auto-search default seed
    handleExpand("account:acc_mule_target");
  }, []);

  useEffect(() => {
    if (selectedCaseId && selectedCaseId !== activeCaseId) {
      setActiveCaseId(selectedCaseId);
      loadCaseNetwork(selectedCaseId);
    }
  }, [selectedCaseId]);

  const loadCases = async () => {
    try {
      const res = await api.listCases();
      const items = res.items || [];
      setCases(items);
      if (!activeCaseId && items.length > 0) {
        setActiveCaseId(items[0].id);
      }
    } catch (err: unknown) {
      console.error(err);
    }
  };

  const loadFindings = async () => {
    try {
      const data = await api.listNetworkFindings(activeCaseId || undefined);
      setFindings(data);
    } catch (err: unknown) {
      console.error(err);
    }
  };

  const loadCandidates = async () => {
    try {
      const data = await api.listEntityLinkCandidates();
      setCandidates(data);
      if (data.length > 0 && !selectedCandidate) {
        setSelectedCandidate(data[0]);
      }
    } catch (err: unknown) {
      console.error(err);
    }
  };

  const handleExpand = async (seedOverride?: string) => {
    const seed = (seedOverride || searchEntity).trim();
    if (!seed) return;
    setLoading(true);
    setError(null);
    setSelectedNode(null);
    setSelectedEdge(null);
    try {
      const sub = await api.expandNeighborhood({
        seed_nodes: [seed],
        max_depth: expandDepth,
        include_shared_attributes: includeWeak,
      });
      setSubgraph(sub);
      layoutNodes(sub.nodes);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  const loadCaseNetwork = async (caseId: string) => {
    if (!caseId) return;
    setLoading(true);
    setError(null);
    setSelectedNode(null);
    setSelectedEdge(null);
    try {
      const sub = await api.getCaseNetwork(caseId, expandDepth, includeWeak);
      setSubgraph(sub);
      layoutNodes(sub.nodes);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  const handleRunAnalysis = async () => {
    const seed = searchEntity.trim() || `case:${activeCaseId}`;
    setLoading(true);
    setError(null);
    setStatusMessage(null);
    try {
      const res = await api.runNetworkAnalysis({
        seed_entities: [seed],
        case_id: activeCaseId || undefined,
        max_depth: expandDepth,
        include_shared_attributes: includeWeak,
      });
      setSubgraph(res.subgraph);
      layoutNodes(res.subgraph.nodes);
      setFindings(res.findings);
      setStatusMessage(
        `Network analysis completed: ${res.findings.length} motifs detected across ${res.subgraph.node_count} nodes.`
      );
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  const handleFindShortestPath = async () => {
    if (!pathSource.trim() || !pathTarget.trim()) return;
    setFindingPath(true);
    setError(null);
    try {
      const res = await api.findShortestPath({
        source_key: pathSource.trim(),
        target_key: pathTarget.trim(),
        include_shared_attributes: includeWeak,
      });
      setPathResult(res);
      if (res.found) {
        layoutNodes(res.nodes);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setFindingPath(false);
    }
  };

  const handleInspectFinding = async (finding: NetworkPatternFinding) => {
    setSelectedFinding(finding);
    setLoadingEvidence(true);
    try {
      const ev = await api.getFindingEvidence(finding.pattern_id);
      setFindingEvidence(ev);
      // Auto-load into explorer subgraph
      setSubgraph({
        installation_id: finding.installation_id,
        seed_nodes: [finding.anchor_entity],
        nodes: ev.nodes,
        edges: ev.edges,
        truncated: false,
        max_depth_reached: 1,
        limitations: ev.limitations,
        node_count: ev.nodes.length,
        edge_count: ev.edges.length,
      });
      layoutNodes(ev.nodes);
    } catch (err: unknown) {
      console.error(err);
    } finally {
      setLoadingEvidence(false);
    }
  };

  const handleSubmitReview = async () => {
    if (!selectedCandidate || !reviewRationale.trim()) return;
    setSubmittingReview(true);
    setError(null);
    try {
      const updated = await api.reviewEntityLink(
        selectedCandidate.candidate_id,
        reviewDecision,
        reviewRationale.trim()
      );
      setStatusMessage(
        `Candidate link updated to '${updated.new_status}' with audit logged.`
      );
      setReviewRationale("");
      await loadCandidates();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmittingReview(false);
    }
  };

  // ---------------------------------------------------------------------------
  // Graph Layout & Force/Circular Positioning
  // ---------------------------------------------------------------------------
  const layoutNodes = (nodes: NetworkNode[]) => {
    const width = 640;
    const height = 420;
    const centerX = width / 2;
    const centerY = height / 2;
    const positions: Record<string, { x: number; y: number }> = {};

    if (nodes.length === 1) {
      positions[nodes[0].node_key] = { x: centerX, y: centerY };
    } else {
      const radius = Math.min(centerX, centerY) * 0.72;
      nodes.forEach((n, idx) => {
        const angle = (2 * Math.PI * idx) / nodes.length;
        positions[n.node_key] = {
          x: Math.round(centerX + radius * Math.cos(angle)),
          y: Math.round(centerY + radius * Math.sin(angle)),
        };
      });
    }
    setNodePositions(positions);
    setPan({ x: 0, y: 0 });
    setZoom(1);
  };

  const handleMouseDownNode = (key: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setDraggingNode(key);
  };

  const handleMouseMoveCanvas = (e: React.MouseEvent) => {
    if (!draggingNode || !svgRef.current) return;
    const rect = svgRef.current.getBoundingClientRect();
    const x = Math.round((e.clientX - rect.left - pan.x) / zoom);
    const y = Math.round((e.clientY - rect.top - pan.y) / zoom);
    setNodePositions((prev) => ({
      ...prev,
      [draggingNode]: { x, y },
    }));
  };

  const handleMouseUpCanvas = () => {
    setDraggingNode(null);
  };

  // Color & styling helper for entity types
  const getNodeColor = (entityType: string): string => {
    switch (entityType.toLowerCase()) {
      case "account":
        return "#3b82f6"; // blue
      case "customer":
        return "#10b981"; // emerald
      case "employee":
        return "#8b5cf6"; // purple
      case "device":
        return "#f97316"; // orange
      case "session":
        return "#06b6d4"; // cyan
      case "branch":
        return "#ec4899"; // pink
      case "beneficiary":
        return "#eab308"; // amber
      default:
        return "#64748b"; // slate
    }
  };

  // Filtered nodes and edges
  const filteredNodes = useMemo(() => {
    if (!subgraph) return [];
    return subgraph.nodes.filter((n) => {
      if (entityTypeFilter !== "all" && n.entity_type !== entityTypeFilter) {
        return false;
      }
      return true;
    });
  }, [subgraph, entityTypeFilter]);

  const filteredNodeKeys = useMemo(
    () => new Set(filteredNodes.map((n) => n.node_key)),
    [filteredNodes]
  );

  const filteredEdges = useMemo(() => {
    if (!subgraph) return [];
    return subgraph.edges.filter((e) => {
      if (!filteredNodeKeys.has(e.source_key) || !filteredNodeKeys.has(e.target_key)) {
        return false;
      }
      if (relTypeFilter !== "all" && e.relationship_type !== relTypeFilter) {
        return false;
      }
      if (!includeWeak && e.evidence_basis === "shared_attribute") {
        return false;
      }
      return true;
    });
  }, [subgraph, filteredNodeKeys, relTypeFilter, includeWeak]);

  return (
    <div className="wb-container" style={{ paddingBottom: 60 }}>
      {/* Top Header */}
      <div className="wb-header-row" style={{ marginBottom: 16 }}>
        <div>
          <h2 className="wb-title" style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span>Network Intelligence & Fraud Graphs</span>
            <span className="chip chip-info" style={{ fontSize: 11 }}>Phase 10 Engine</span>
          </h2>
          <p className="wb-subtitle">
            Evidence-backed relational intelligence, bounded graph traversal, transaction motifs,
            and controlled entity resolution.
          </p>
        </div>

        {/* Action Controls */}
        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          {cases.length > 0 && (
            <select
              className="wb-input"
              style={{ width: 220 }}
              value={activeCaseId}
              onChange={(e) => {
                setActiveCaseId(e.target.value);
                if (onSelectCase) onSelectCase(e.target.value);
                loadCaseNetwork(e.target.value);
              }}
            >
              <option value="">-- Active Case Filter --</option>
              {cases.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.label} ({c.id.slice(0, 8)})
                </option>
              ))}
            </select>
          )}

          <button
            className="wb-btn wb-btn-primary"
            disabled={loading}
            onClick={handleRunAnalysis}
            title="Execute complete multi-hop motif detection & network analysis"
          >
            {loading ? "Analyzing..." : "Run Network Analysis"}
          </button>
        </div>
      </div>

      {/* Notifications */}
      {statusMessage && (
        <div className="wb-alert wb-alert-success" style={{ marginBottom: 16 }}>
          {statusMessage}
        </div>
      )}
      {error && (
        <div className="wb-alert wb-alert-danger" style={{ marginBottom: 16 }}>
          {error}
        </div>
      )}

      {/* Sub-Navigation Tabs */}
      <div className="wb-subnav" style={{ marginBottom: 20 }}>
        <button
          className={`wb-tab ${subTab === "explorer" ? "active" : ""}`}
          onClick={() => setSubTab("explorer")}
        >
          A. Network Explorer
        </button>
        <button
          className={`wb-tab ${subTab === "transactions" ? "active" : ""}`}
          onClick={() => setSubTab("transactions")}
        >
          B. Transaction Networks ({findings.length})
        </button>
        <button
          className={`wb-tab ${subTab === "case_network" ? "active" : ""}`}
          onClick={() => setSubTab("case_network")}
        >
          C. Case Network
        </button>
        <button
          className={`wb-tab ${subTab === "findings" ? "active" : ""}`}
          onClick={() => setSubTab("findings")}
        >
          D. Pattern Findings ({findings.length})
        </button>
        <button
          className={`wb-tab ${subTab === "entity_links" ? "active" : ""}`}
          onClick={() => setSubTab("entity_links")}
        >
          E. Entity Link Review ({candidates.length})
        </button>
      </div>

      {/* ========================================================================= */}
      {/* VIEW A: NETWORK EXPLORER & INTERACTIVE GRAPH                              */}
      {/* ========================================================================= */}
      {subTab === "explorer" && (
        <div>
          {/* Search & Traversal Controls Card */}
          <div className="wb-card" style={{ marginBottom: 16, padding: 14 }}>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 12, alignItems: "center" }}>
              <div style={{ flex: "1 1 240px" }}>
                <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block" }}>
                  Seed Entity Reference
                </label>
                <input
                  type="text"
                  className="wb-input"
                  style={{ width: "100%", fontFamily: "var(--font-mono)" }}
                  placeholder="e.g. account:acc_mule_target or customer:cif_100"
                  value={searchEntity}
                  onChange={(e) => setSearchEntity(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleExpand()}
                />
              </div>

              <div style={{ width: 120 }}>
                <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block" }}>
                  Max Depth: {expandDepth}
                </label>
                <input
                  type="range"
                  min="1"
                  max="4"
                  value={expandDepth}
                  onChange={(e) => setExpandDepth(parseInt(e.target.value))}
                  style={{ width: "100%" }}
                />
              </div>

              <div style={{ width: 140 }}>
                <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block" }}>
                  Entity Type
                </label>
                <select
                  className="wb-input"
                  style={{ width: "100%" }}
                  value={entityTypeFilter}
                  onChange={(e) => setEntityTypeFilter(e.target.value)}
                >
                  <option value="all">All Types</option>
                  <option value="account">Accounts</option>
                  <option value="customer">Customers</option>
                  <option value="employee">Employees</option>
                  <option value="device">Devices</option>
                  <option value="session">Sessions</option>
                </select>
              </div>

              <div style={{ width: 150 }}>
                <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block" }}>
                  Relationship Type
                </label>
                <select
                  className="wb-input"
                  style={{ width: "100%" }}
                  value={relTypeFilter}
                  onChange={(e) => setRelTypeFilter(e.target.value)}
                >
                  <option value="all">All Relationships</option>
                  <option value="transferred_funds_to">Transfers</option>
                  <option value="accessed_via_device">Device Access</option>
                  <option value="associated_with">Associations</option>
                </select>
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: 6, paddingTop: 14 }}>
                <input
                  type="checkbox"
                  id="toggle-weak"
                  checked={includeWeak}
                  onChange={(e) => setIncludeWeak(e.target.checked)}
                />
                <label htmlFor="toggle-weak" style={{ fontSize: 12, cursor: "pointer" }}>
                  Include Weak Attributes
                </label>
              </div>

              <div style={{ paddingTop: 14 }}>
                <button
                  className="wb-btn wb-btn-primary"
                  onClick={() => handleExpand()}
                  disabled={loading}
                >
                  Expand Neighborhood
                </button>
              </div>
            </div>

            {subgraph?.truncated && (
              <div
                style={{
                  marginTop: 10,
                  fontSize: 12,
                  color: "var(--accent-amber)",
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                }}
              >
                <strong>Truncation Notice:</strong> {subgraph.truncation_reason || "Expansion truncated by bounds"}. Full network not shown to prevent explosion.
              </div>
            )}
          </div>

          {/* Interactive Graph Canvas and Evidence Panel */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 340px", gap: 16 }}>
            {/* Graph Canvas Container */}
            <div
              className="wb-card"
              style={{
                position: "relative",
                height: 520,
                padding: 0,
                overflow: "hidden",
                background: "#0a0f1d",
              }}
            >
              {/* Canvas Overlay Controls */}
              <div
                style={{
                  position: "absolute",
                  top: 12,
                  left: 12,
                  zIndex: 10,
                  display: "flex",
                  gap: 6,
                  background: "rgba(15,23,42,0.85)",
                  padding: "4px 8px",
                  borderRadius: 6,
                  border: "1px solid var(--border-color)",
                }}
              >
                <button
                  className="wb-btn"
                  style={{ padding: "2px 8px", fontSize: 12 }}
                  onClick={() => setZoom((z) => Math.min(2.5, z + 0.2))}
                >
                  +
                </button>
                <button
                  className="wb-btn"
                  style={{ padding: "2px 8px", fontSize: 12 }}
                  onClick={() => setZoom((z) => Math.max(0.4, z - 0.2))}
                >
                  -
                </button>
                <button
                  className="wb-btn"
                  style={{ padding: "2px 8px", fontSize: 12 }}
                  onClick={() => {
                    setZoom(1);
                    setPan({ x: 0, y: 0 });
                  }}
                >
                  Reset
                </button>
                <span
                  style={{
                    fontSize: 11,
                    color: "var(--text-muted)",
                    display: "flex",
                    alignItems: "center",
                    marginLeft: 6,
                  }}
                >
                  {filteredNodes.length} nodes, {filteredEdges.length} edges
                </span>
              </div>

              {/* Legend Overlay */}
              <div
                style={{
                  position: "absolute",
                  bottom: 12,
                  left: 12,
                  zIndex: 10,
                  display: "flex",
                  gap: 12,
                  background: "rgba(15,23,42,0.85)",
                  padding: "6px 12px",
                  borderRadius: 6,
                  fontSize: 11,
                  border: "1px solid var(--border-color)",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                  <span style={{ width: 10, height: 10, borderRadius: 2, background: "#3b82f6" }} />
                  Account
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                  <span style={{ width: 10, height: 10, borderRadius: 2, background: "#10b981" }} />
                  Customer
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                  <span style={{ width: 10, height: 10, borderRadius: 2, background: "#8b5cf6" }} />
                  Employee
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                  <span style={{ width: 10, height: 10, borderRadius: 2, background: "#f97316" }} />
                  Device
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                  <span style={{ width: 16, height: 2, background: "#94a3b8" }} />
                  Observed
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                  <span style={{ width: 16, height: 2, borderBottom: "2px dashed #94a3b8" }} />
                  Inferred
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                  <span style={{ width: 16, height: 2, borderBottom: "2px dotted #f97316" }} />
                  Weak
                </div>
              </div>

              {/* Interactive SVG Surface */}
              <svg
                ref={svgRef}
                width="100%"
                height="100%"
                style={{ cursor: draggingNode ? "grabbing" : "grab" }}
                onMouseMove={handleMouseMoveCanvas}
                onMouseUp={handleMouseUpCanvas}
                onMouseLeave={handleMouseUpCanvas}
              >
                <defs>
                  {/* Directed Arrow Marker for Transactions */}
                  <marker
                    id="arrow-observed"
                    viewBox="0 0 10 10"
                    refX="22"
                    refY="5"
                    markerWidth="6"
                    markerHeight="6"
                    orient="auto-start-reverse"
                  >
                    <path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8" />
                  </marker>
                  <marker
                    id="arrow-weak"
                    viewBox="0 0 10 10"
                    refX="22"
                    refY="5"
                    markerWidth="6"
                    markerHeight="6"
                    orient="auto-start-reverse"
                  >
                    <path d="M 0 1 L 10 5 L 0 9 z" fill="#f97316" />
                  </marker>
                </defs>

                <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
                  {/* Edges */}
                  {filteredEdges.map((e) => {
                    const src = nodePositions[e.source_key];
                    const tgt = nodePositions[e.target_key];
                    if (!src || !tgt) return null;

                    const isSelected = selectedEdge?.edge_id === e.edge_id;
                    const isWeak = e.evidence_basis === "shared_attribute";
                    const isDerived = e.evidence_basis === "derived_relationship";

                    return (
                      <g key={e.edge_id} style={{ cursor: "pointer" }} onClick={() => setSelectedEdge(e)}>
                        <line
                          x1={src.x}
                          y1={src.y}
                          x2={tgt.x}
                          y2={tgt.y}
                          stroke={isSelected ? "#ec4899" : isWeak ? "#f97316" : "#38bdf8"}
                          strokeWidth={isSelected ? 3.5 : isWeak ? 1.5 : 2}
                          strokeDasharray={isWeak ? "3,3" : isDerived ? "6,4" : undefined}
                          opacity={isWeak ? 0.6 : 0.85}
                          markerEnd={e.directed ? (isWeak ? "url(#arrow-weak)" : "url(#arrow-observed)") : undefined}
                        />
                        {/* Edge Label for Transfers */}
                        {Boolean(e.attributes?.amount) && (
                          <text
                            x={(src.x + tgt.x) / 2}
                            y={(src.y + tgt.y) / 2 - 6}
                            fill="#94a3b8"
                            fontSize="10"
                            textAnchor="middle"
                            fontFamily="var(--font-mono)"
                          >
                            {String(e.attributes.currency || "")} {String(e.attributes.amount)}
                          </text>
                        )}
                      </g>
                    );
                  })}

                  {/* Nodes */}
                  {filteredNodes.map((n) => {
                    const pos = nodePositions[n.node_key] || { x: 300, y: 200 };
                    const isSelected = selectedNode?.node_key === n.node_key;
                    const nodeColor = getNodeColor(n.entity_type);

                    return (
                      <g
                        key={n.node_key}
                        transform={`translate(${pos.x}, ${pos.y})`}
                        style={{ cursor: "pointer" }}
                        onMouseDown={(e) => handleMouseDownNode(n.node_key, e)}
                        onClick={() => {
                          setSelectedNode(n);
                          setSelectedEdge(null);
                        }}
                      >
                        {/* Halo for Selected Node */}
                        {isSelected && (
                          <circle r="22" fill="none" stroke="#f43f5e" strokeWidth="2.5" strokeDasharray="3,3" />
                        )}

                        {/* Node Shape */}
                        <circle
                          r="16"
                          fill={nodeColor}
                          stroke="#0f172a"
                          strokeWidth="2"
                          opacity={0.95}
                        />

                        {/* Node Label */}
                        <text
                          y="26"
                          textAnchor="middle"
                          fill="#f8fafc"
                          fontSize="11"
                          fontFamily="var(--font-mono)"
                          fontWeight="500"
                        >
                          {n.pseudonymous_label}
                        </text>
                        <text
                          y="-20"
                          textAnchor="middle"
                          fill="#94a3b8"
                          fontSize="9"
                          style={{ textTransform: "uppercase" }}
                        >
                          {n.entity_type}
                        </text>
                      </g>
                    );
                  })}
                </g>
              </svg>
            </div>

            {/* Evidence & Details Side Panel */}
            <div className="wb-card" style={{ height: 520, overflowY: "auto", padding: 16 }}>
              {selectedNode ? (
                <div>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span className="chip" style={{ background: getNodeColor(selectedNode.entity_type), color: "#fff" }}>
                      {selectedNode.entity_type}
                    </span>
                    <button
                      className="wb-btn"
                      style={{ fontSize: 10, padding: "2px 6px" }}
                      onClick={() => setSelectedNode(null)}
                    >
                      Clear
                    </button>
                  </div>

                  <h3 style={{ fontSize: 16, marginTop: 10, marginBottom: 4, fontFamily: "var(--font-mono)" }}>
                    {selectedNode.pseudonymous_label}
                  </h3>
                  <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 12 }}>
                    Key: {selectedNode.node_key}
                  </div>

                  {selectedNode.first_seen && (
                    <div style={{ fontSize: 12, marginBottom: 6 }}>
                      <span style={{ color: "var(--text-muted)" }}>First Seen: </span>
                      {new Date(selectedNode.first_seen).toLocaleString()}
                    </div>
                  )}

                  <h4 style={{ fontSize: 13, marginTop: 16, marginBottom: 8 }}>Attributes & Telemetry</h4>
                  {Object.keys(selectedNode.attributes).length === 0 ? (
                    <div style={{ fontSize: 12, color: "var(--text-muted)" }}>No custom attributes.</div>
                  ) : (
                    <pre
                      style={{
                        background: "rgba(0,0,0,0.3)",
                        padding: 8,
                        borderRadius: 4,
                        fontSize: 11,
                        overflowX: "auto",
                      }}
                    >
                      {JSON.stringify(selectedNode.attributes, null, 2)}
                    </pre>
                  )}

                  <div style={{ marginTop: 20 }}>
                    <button
                      className="wb-btn wb-btn-primary"
                      style={{ width: "100%", fontSize: 12 }}
                      onClick={() => handleExpand(selectedNode.node_key)}
                    >
                      Expand From This Entity
                    </button>
                  </div>
                </div>
              ) : selectedEdge ? (
                <div>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span className="chip chip-info" style={{ fontSize: 11 }}>
                      {selectedEdge.relationship_type}
                    </span>
                    <button
                      className="wb-btn"
                      style={{ fontSize: 10, padding: "2px 6px" }}
                      onClick={() => setSelectedEdge(null)}
                    >
                      Clear
                    </button>
                  </div>

                  <h4 style={{ fontSize: 14, marginTop: 10, marginBottom: 4 }}>
                    {selectedEdge.source_key} &rarr; {selectedEdge.target_key}
                  </h4>

                  <div style={{ fontSize: 12, marginTop: 10, marginBottom: 6 }}>
                    <span style={{ color: "var(--text-muted)" }}>Basis: </span>
                    <strong style={{ color: selectedEdge.evidence_basis === "shared_attribute" ? "var(--accent-amber)" : "var(--accent-blue)" }}>
                      {selectedEdge.evidence_basis}
                    </strong>
                  </div>

                  <div style={{ fontSize: 12, marginBottom: 6 }}>
                    <span style={{ color: "var(--text-muted)" }}>Confidence: </span>
                    {(selectedEdge.confidence * 100).toFixed(0)}%
                  </div>

                  <h4 style={{ fontSize: 13, marginTop: 14, marginBottom: 6 }}>Supporting Evidence</h4>
                  <div style={{ fontSize: 12, marginBottom: 4 }}>
                    <span style={{ color: "var(--text-muted)" }}>Sources: </span>
                    {selectedEdge.source_systems.join(", ") || "None"}
                  </div>
                  <div style={{ fontSize: 12, marginBottom: 4 }}>
                    <span style={{ color: "var(--text-muted)" }}>Events: </span>
                    {selectedEdge.event_ids.length > 0 ? selectedEdge.event_ids.join(", ") : "Canonical"}
                  </div>

                  {Boolean(selectedEdge.attributes?.amount) && (
                    <div
                      style={{
                        marginTop: 12,
                        padding: 8,
                        background: "rgba(59,130,246,0.1)",
                        borderRadius: 4,
                        border: "1px solid rgba(59,130,246,0.3)",
                      }}
                    >
                      <div style={{ fontSize: 11, color: "var(--text-muted)" }}>Transfer Amount</div>
                      <div style={{ fontSize: 15, fontWeight: "bold", fontFamily: "var(--font-mono)" }}>
                        {String(selectedEdge.attributes.currency || "")} {String(selectedEdge.attributes.amount)}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div style={{ color: "var(--text-muted)", fontSize: 13, textAlign: "center", marginTop: 80 }}>
                  Select any node or edge on the canvas to inspect evidence, telemetry, and limitations.
                </div>
              )}
            </div>
          </div>

          {/* Shortest Path Finder Toolbar */}
          <div className="wb-card" style={{ marginTop: 16, padding: 14 }}>
            <h4 style={{ fontSize: 14, marginBottom: 8 }}>Evidence-Backed Shortest Path Discovery</h4>
            <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
              <input
                type="text"
                className="wb-input"
                style={{ flex: 1, fontFamily: "var(--font-mono)" }}
                placeholder="Source Node (e.g. account:acc_src_1)"
                value={pathSource}
                onChange={(e) => setPathSource(e.target.value)}
              />
              <span>&rarr;</span>
              <input
                type="text"
                className="wb-input"
                style={{ flex: 1, fontFamily: "var(--font-mono)" }}
                placeholder="Target Node (e.g. account:acc_beneficiary)"
                value={pathTarget}
                onChange={(e) => setPathTarget(e.target.value)}
              />
              <button
                className="wb-btn wb-btn-primary"
                disabled={findingPath}
                onClick={handleFindShortestPath}
              >
                {findingPath ? "Traversing..." : "Discover Path"}
              </button>
            </div>

            {pathResult && (
              <div style={{ marginTop: 12, fontSize: 13 }}>
                {pathResult.found ? (
                  <div style={{ color: "var(--accent-green)" }}>
                    Path identified ({pathResult.path_length} hops):{" "}
                    <strong>{pathResult.nodes.map((n) => n.pseudonymous_label).join(" → ")}</strong>
                  </div>
                ) : (
                  <div style={{ color: "var(--accent-amber)" }}>
                    No evidence-backed path found between entities within max traversal depth.
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* VIEW B: TRANSACTION NETWORKS & MOTIFS                                     */}
      {/* ========================================================================= */}
      {subTab === "transactions" && (
        <div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
            {findings.map((f) => (
              <div key={f.pattern_id} className="wb-card" style={{ borderLeft: "4px solid #3b82f6" }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                  <span className="chip chip-info" style={{ textTransform: "uppercase", fontSize: 11 }}>
                    {f.pattern_type.replace(/_/g, " ")}
                  </span>
                  <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                    Confidence: {(f.confidence * 100).toFixed(0)}%
                  </span>
                </div>

                <h4 style={{ fontSize: 15, margin: "0 0 6px 0" }}>{f.anchor_entity}</h4>
                <p style={{ fontSize: 13, color: "var(--text-color)", marginBottom: 12 }}>
                  {f.explanation}
                </p>

                {f.monetary_total && (
                  <div style={{ marginBottom: 10, fontSize: 13 }}>
                    <span style={{ color: "var(--text-muted)" }}>Observed Volume: </span>
                    <strong style={{ fontFamily: "var(--font-mono)" }}>
                      {f.currency} {f.monetary_total}
                    </strong>
                  </div>
                )}

                <div style={{ fontSize: 12, marginBottom: 8 }}>
                  <span style={{ color: "var(--text-muted)" }}>Connected Entities: </span>
                  {f.related_entities.join(", ")}
                </div>

                {/* Limitations Alert */}
                <div
                  style={{
                    background: "rgba(245,158,11,0.08)",
                    borderLeft: "3px solid #f59e0b",
                    padding: "6px 10px",
                    borderRadius: 3,
                    fontSize: 11,
                    marginBottom: 8,
                  }}
                >
                  <strong>Evidence Limitations:</strong>
                  <ul style={{ margin: "4px 0 0 16px", padding: 0 }}>
                    {f.evidence_limitations.map((lim, i) => (
                      <li key={i}>{lim}</li>
                    ))}
                  </ul>
                </div>

                {/* Alternative Explanations */}
                <div
                  style={{
                    background: "rgba(16,185,129,0.08)",
                    borderLeft: "3px solid #10b981",
                    padding: "6px 10px",
                    borderRadius: 3,
                    fontSize: 11,
                    marginBottom: 12,
                  }}
                >
                  <strong>Alternative Legitimate Explanations:</strong>
                  <ul style={{ margin: "4px 0 0 16px", padding: 0 }}>
                    {f.alternative_legitimate_explanations.map((alt, i) => (
                      <li key={i}>{alt}</li>
                    ))}
                  </ul>
                </div>

                <button
                  className="wb-btn"
                  style={{ width: "100%", fontSize: 12 }}
                  onClick={() => {
                    handleInspectFinding(f);
                    setSubTab("explorer");
                  }}
                >
                  Visualize Subgraph on Canvas
                </button>
              </div>
            ))}
          </div>

          {findings.length === 0 && (
            <div className="wb-card" style={{ textAlign: "center", padding: 40, color: "var(--text-muted)" }}>
              No transaction motifs detected in the selected window. Click "Run Network Analysis" above to mine multi-hop patterns.
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* VIEW C: CASE NETWORK                                                      */}
      {/* ========================================================================= */}
      {subTab === "case_network" && (
        <div>
          <div className="wb-card" style={{ marginBottom: 16 }}>
            <h3 style={{ fontSize: 16, marginBottom: 8 }}>
              Connected Entities for Investigation: {activeCaseId || "None"}
            </h3>
            <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 16 }}>
              Cross-system entity neighborhood relevant to this active investigation, linking
              Phase 7 attack reconstructions and Phase 9 institutional memory typologies.
            </p>

            <div style={{ display: "flex", gap: 12 }}>
              <button
                className="wb-btn wb-btn-primary"
                onClick={() => {
                  loadCaseNetwork(activeCaseId);
                  setSubTab("explorer");
                }}
              >
                Render Case Subgraph on Canvas
              </button>

              {onNavigateTab && (
                <>
                  <button
                    className="wb-btn"
                    onClick={() => onNavigateTab("intelligence")}
                  >
                    View Phase 7 Attack Reconstruction
                  </button>
                  <button
                    className="wb-btn"
                    onClick={() => onNavigateTab("memory")}
                  >
                    View Phase 9 Fraud DNA Matches
                  </button>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* VIEW D: NETWORK FINDINGS LIST                                              */}
      {/* ========================================================================= */}
      {subTab === "findings" && (
        <div className="wb-card">
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: "1px solid var(--border-color)", textAlign: "left", color: "var(--text-muted)" }}>
                <th style={{ padding: 10 }}>Pattern Type</th>
                <th style={{ padding: 10 }}>Anchor Entity</th>
                <th style={{ padding: 10 }}>Related Entities</th>
                <th style={{ padding: 10 }}>Monetary Flow</th>
                <th style={{ padding: 10 }}>Confidence</th>
                <th style={{ padding: 10 }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <tr key={f.pattern_id} style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                  <td style={{ padding: 10 }}>
                    <span className="chip chip-info" style={{ fontSize: 11 }}>{f.pattern_type}</span>
                  </td>
                  <td style={{ padding: 10, fontFamily: "var(--font-mono)" }}>{f.anchor_entity}</td>
                  <td style={{ padding: 10 }}>{f.related_entities.length} entities</td>
                  <td style={{ padding: 10, fontFamily: "var(--font-mono)" }}>
                    {f.monetary_total ? `${f.currency} ${f.monetary_total}` : "N/A"}
                  </td>
                  <td style={{ padding: 10 }}>{(f.confidence * 100).toFixed(0)}%</td>
                  <td style={{ padding: 10 }}>
                    <button
                      className="wb-btn"
                      style={{ fontSize: 11 }}
                      onClick={() => {
                        handleInspectFinding(f);
                        setSubTab("explorer");
                      }}
                    >
                      Inspect Evidence
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {loadingEvidence && (
            <div style={{ padding: 16, color: "var(--text-muted)" }}>Loading evidence subgraph...</div>
          )}
          {selectedFinding && findingEvidence && (
            <div className="wb-card" style={{ marginTop: 16, borderTop: "3px solid #3b82f6" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <h4 style={{ margin: 0 }}>Evidence Subgraph for Finding: {selectedFinding.pattern_id}</h4>
                <button className="wb-btn" style={{ fontSize: 11 }} onClick={() => setSelectedFinding(null)}>
                  Close
                </button>
              </div>
              <p style={{ fontSize: 13, marginTop: 8 }}>{findingEvidence.explanation}</p>
              <div style={{ fontSize: 12, marginTop: 8 }}>
                <strong>Missing Information: </strong>
                {findingEvidence.missing_information.length > 0
                  ? findingEvidence.missing_information.join("; ")
                  : "None noted"}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* VIEW E: ENTITY LINK REVIEW QUEUE                                          */}
      {/* ========================================================================= */}
      {subTab === "entity_links" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 380px", gap: 16 }}>
          {/* Candidates Table */}
          <div className="wb-card">
            <h3 style={{ fontSize: 16, marginBottom: 4 }}>Proposed Entity Relationship Candidates</h3>
            <p style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 16 }}>
              Human review queue: shared attributes do not prove common ownership without corroborating evidence.
            </p>

            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
              <thead>
                <tr style={{ borderBottom: "1px solid var(--border-color)", textAlign: "left", color: "var(--text-muted)" }}>
                  <th style={{ padding: 8 }}>Entities</th>
                  <th style={{ padding: 8 }}>Shared Attribute</th>
                  <th style={{ padding: 8 }}>Status</th>
                  <th style={{ padding: 8 }}>Confidence</th>
                  <th style={{ padding: 8 }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {candidates.map((c) => {
                  const isSelected = selectedCandidate?.candidate_id === c.candidate_id;
                  return (
                    <tr
                      key={c.candidate_id}
                      style={{
                        borderBottom: "1px solid rgba(255,255,255,0.05)",
                        background: isSelected ? "rgba(59,130,246,0.1)" : undefined,
                      }}
                    >
                      <td style={{ padding: 8, fontFamily: "var(--font-mono)", fontSize: 12 }}>
                        {c.source_entity_key} &harr; {c.target_entity_key}
                      </td>
                      <td style={{ padding: 8 }}>
                        <span className="chip" style={{ fontSize: 11 }}>
                          {c.attribute_type}: {c.attribute_value}
                        </span>
                      </td>
                      <td style={{ padding: 8 }}>
                        <span
                          className={`chip ${
                            c.status === "SAME_ENTITY_CONFIRMED"
                              ? "chip-success"
                              : c.status === "RELATIONSHIP_DISPROVEN"
                              ? "chip-danger"
                              : "chip-warning"
                          }`}
                          style={{ fontSize: 11 }}
                        >
                          {c.status}
                        </span>
                      </td>
                      <td style={{ padding: 8 }}>{(c.confidence * 100).toFixed(0)}%</td>
                      <td style={{ padding: 8 }}>
                        <button
                          className="wb-btn"
                          style={{ fontSize: 11 }}
                          onClick={() => setSelectedCandidate(c)}
                        >
                          Review
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Review Decision Form */}
          <div className="wb-card">
            <h4 style={{ fontSize: 15, marginBottom: 12 }}>Candidate Governance Review</h4>

            {selectedCandidate ? (
              <div>
                <div style={{ fontSize: 12, marginBottom: 8 }}>
                  <span style={{ color: "var(--text-muted)" }}>Source: </span>
                  <code style={{ fontFamily: "var(--font-mono)" }}>{selectedCandidate.source_entity_key}</code>
                </div>
                <div style={{ fontSize: 12, marginBottom: 8 }}>
                  <span style={{ color: "var(--text-muted)" }}>Target: </span>
                  <code style={{ fontFamily: "var(--font-mono)" }}>{selectedCandidate.target_entity_key}</code>
                </div>
                <div style={{ fontSize: 12, marginBottom: 12 }}>
                  <span style={{ color: "var(--text-muted)" }}>Matched Via: </span>
                  <strong>{selectedCandidate.attribute_type} ({selectedCandidate.attribute_value})</strong>
                </div>

                {canReview ? (
                  <div>
                    <label style={{ fontSize: 12, display: "block", marginBottom: 4 }}>
                      Adjudication Decision
                    </label>
                    <select
                      className="wb-input"
                      style={{ width: "100%", marginBottom: 12 }}
                      value={reviewDecision}
                      onChange={(e) => setReviewDecision(e.target.value)}
                    >
                      <option value="SAME_ENTITY_CONFIRMED">SAME_ENTITY_CONFIRMED (Confirmed Identity)</option>
                      <option value="POSSIBLY_RELATED">POSSIBLY_RELATED (Under Investigation)</option>
                      <option value="SHARED_ATTRIBUTE_ONLY">SHARED_ATTRIBUTE_ONLY (Weaker Association)</option>
                      <option value="RELATIONSHIP_DISPROVEN">RELATIONSHIP_DISPROVEN (Confirmed Unrelated)</option>
                    </select>

                    <label style={{ fontSize: 12, display: "block", marginBottom: 4 }}>
                      Review Rationale (Mandatory)
                    </label>
                    <textarea
                      className="wb-input"
                      rows={4}
                      style={{ width: "100%", marginBottom: 12, fontSize: 12 }}
                      placeholder="Document verified justification, source documents, or branch interview notes..."
                      value={reviewRationale}
                      onChange={(e) => setReviewRationale(e.target.value)}
                    />

                    <button
                      className="wb-btn wb-btn-primary"
                      style={{ width: "100%" }}
                      disabled={submittingReview || !reviewRationale.trim()}
                      onClick={handleSubmitReview}
                    >
                      {submittingReview ? "Recording..." : "Record Review Decision"}
                    </button>
                  </div>
                ) : (
                  <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                    Your current role does not have authorization to approve or reject entity relationships.
                  </div>
                )}
              </div>
            ) : (
              <div style={{ color: "var(--text-muted)", fontSize: 13, textAlign: "center", marginTop: 40 }}>
                Select a candidate from the queue to review supporting evidence and record a governance decision.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
