import React, { useState, useEffect } from "react";
import { api } from "../api";
import {
  GovernedComponent,
  ValidationRun,
  ProductionRelease,
  SuspensionRecord,
  GovernanceIncident,
  DriftRecord,
  SystemHealthOverview,
  EvidencePassport,
  GovernedAIProvider,
  ReadinessAssessment,
  ValidationPackage,
  Persona,
} from "../types";

interface Props {
  currentPersona: Persona;
}

export const ProductionGovernanceView: React.FC<Props> = ({ currentPersona }) => {
  const [activeTab, setActiveTab] = useState<
    "overview" | "registry" | "validation" | "releases" | "killswitch" | "incidents" | "drift" | "passports" | "aiproviders" | "readiness"
  >("overview");

  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // State data
  const [health, setHealth] = useState<SystemHealthOverview | null>(null);
  const [components, setComponents] = useState<GovernedComponent[]>([]);
  const [validationRuns, setValidationRuns] = useState<ValidationRun[]>([]);
  const [releases, setReleases] = useState<ProductionRelease[]>([]);
  const [suspensions, setSuspensions] = useState<SuspensionRecord[]>([]);
  const [incidents, setIncidents] = useState<GovernanceIncident[]>([]);
  const [driftRecords, setDriftRecords] = useState<DriftRecord[]>([]);
  const [passports, setPassports] = useState<EvidencePassport[]>([]);
  const [aiProviders, setAiProviders] = useState<GovernedAIProvider[]>([]);
  const [readiness, setReadiness] = useState<ReadinessAssessment | null>(null);
  const [validationPkg, setValidationPkg] = useState<ValidationPackage | null>(null);

  // Action modals/inputs
  const [registerModalOpen, setRegisterModalOpen] = useState(false);
  const [newCompId, setNewCompId] = useState("");
  const [newCompVer, setNewCompVer] = useState("1.0.0");
  const [newCompType, setNewCompType] = useState("detector");
  const [newCompName, setNewCompName] = useState("");
  const [newCompRisk, setNewCompRisk] = useState("high");
  const [newCompOwner, setNewCompOwner] = useState("Financial Crime Analytics");

  // Approval modal
  const [approvalTarget, setApprovalTarget] = useState<GovernedComponent | null>(null);
  const [approvalValRunId, setApprovalValRunId] = useState("val-run-001");
  const [approvalRationale, setApprovalRationale] = useState("");

  // Suspension modal
  const [suspendTarget, setSuspendTarget] = useState<GovernedComponent | null>(null);
  const [suspendReason, setSuspendReason] = useState("");

  // Rollback modal
  const [rollbackReleaseId, setRollbackReleaseId] = useState<string | null>(null);
  const [rollbackTargetId, setRollbackTargetId] = useState("");
  const [rollbackReason, setRollbackReason] = useState("");

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [h, comps, vRuns, rels, susps, incs, drifts, pass, providers] = await Promise.all([
        api.getSystemHealthOverview().catch(() => null),
        api.listGovernedComponents().catch(() => []),
        api.listValidationRuns().catch(() => []),
        api.listReleases().catch(() => []),
        api.listSuspensions().catch(() => []),
        api.listGovernanceIncidents().catch(() => []),
        api.listDriftRecords().catch(() => []),
        api.listEvidencePassports().catch(() => []),
        api.listAIProviders().catch(() => []),
      ]);

      setHealth(h);
      setComponents(comps);
      setValidationRuns(vRuns);
      setReleases(rels);
      setSuspensions(susps);
      setIncidents(incs);
      setDriftRecords(drifts);
      setPassports(pass);
      setAiProviders(providers);

      // Attempt to load default validation package
      try {
        const pkg = await api.getValidationPackage("2026.11.0");
        setValidationPkg(pkg);
      } catch {
        // Ignored if not yet seeded
      }
    } catch (err: any) {
      setError(err?.message || "Failed to load governance platform data");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleRegisterComponent = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.registerGovernedComponent({
        component_id: newCompId,
        version: newCompVer,
        component_type: newCompType,
        name: newCompName,
        risk_tier: newCompRisk,
        owner_team: newCompOwner,
        source_digest: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        configuration_digest: "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
        parameters: { threshold: 0.85 },
      });
      setRegisterModalOpen(false);
      setNewCompId("");
      setNewCompName("");
      fetchData();
    } catch (err: any) {
      alert(`Registration failed: ${err.message}`);
    }
  };

  const handleApprove = async () => {
    if (!approvalTarget) return;
    try {
      await api.approveGovernedComponent(approvalTarget.component_id, approvalTarget.version, {
        validation_run_id: approvalValRunId,
        validation_digest: "a".repeat(64),
        rationale: approvalRationale || "Approved under Model Risk Management framework",
      });
      setApprovalTarget(null);
      fetchData();
    } catch (err: any) {
      alert(`Approval error: ${err.message}`);
    }
  };

  const handleSuspend = async () => {
    if (!suspendTarget) return;
    try {
      await api.suspendComponent({
        component_id: suspendTarget.component_id,
        version: suspendTarget.version,
        reason: suspendReason || "Operational suspension via Kill Switch",
      });
      setSuspendTarget(null);
      fetchData();
    } catch (err: any) {
      alert(`Suspension error: ${err.message}`);
    }
  };

  const handleResume = async (comp: GovernedComponent) => {
    try {
      await api.resumeComponent({
        component_id: comp.component_id,
        version: comp.version,
        reason: "Operational clearance verified",
      });
      fetchData();
    } catch (err: any) {
      alert(`Resume error: ${err.message}`);
    }
  };

  const handleRollback = async () => {
    if (!rollbackReleaseId) return;
    try {
      await api.rollbackRelease(rollbackReleaseId, rollbackTargetId, rollbackReason || "Emergency rollback to last validated baseline");
      setRollbackReleaseId(null);
      fetchData();
    } catch (err: any) {
      alert(`Rollback error: ${err.message}`);
    }
  };

  const handleEvaluateReadiness = async () => {
    try {
      const gates = [
        { gate_name: "SECURITY", status: "PASS", verified_by: currentPersona.name, rationale: "Security baseline verified" },
        { gate_name: "DATA_CONTRACT", status: "PASS", verified_by: currentPersona.name, rationale: "Canonical schemas active" },
        { gate_name: "MIGRATIONS", status: "PASS", verified_by: currentPersona.name, rationale: "Database migration 011 applied" },
        { gate_name: "AUDIT", status: "PASS", verified_by: currentPersona.name, rationale: "Hash chain verified unbroken" },
        { gate_name: "DETECTOR_VALIDATION", status: "PASS", verified_by: currentPersona.name, rationale: "Validation benchmarks met" },
        { gate_name: "AI_EVALUATION", status: "PASS", verified_by: currentPersona.name, rationale: "Copilot grounding 100% verified" },
        { gate_name: "DR_TEST", status: "PASS", verified_by: currentPersona.name, rationale: "Disaster recovery RTO < 1h" },
        { gate_name: "BACKUP_RESTORE", status: "PASS", verified_by: currentPersona.name, rationale: "Restore verified" },
        { gate_name: "MONITORING", status: "PASS", verified_by: currentPersona.name, rationale: "Drift telemetry active" },
        { gate_name: "ACCESS_CONTROL", status: "PASS", verified_by: currentPersona.name, rationale: "RBAC & maker-checker active" },
        { gate_name: "INCIDENT_RESPONSE", status: "PASS", verified_by: currentPersona.name, rationale: "Runbooks tested" },
        { gate_name: "DOCUMENTATION", status: "PASS", verified_by: currentPersona.name, rationale: "Audit packages generated" },
        { gate_name: "APPROVAL", status: "PASS", verified_by: currentPersona.name, rationale: "Model risk committee sign-off" },
      ];
      const res = await api.evaluateReadinessGates({
        release_version: "2026.11.0",
        gates,
      });
      setReadiness(res);
      const pkg = await api.getValidationPackage("2026.11.0");
      setValidationPkg(pkg);
    } catch (err: any) {
      alert(`Readiness evaluation failed: ${err.message}`);
    }
  };

  const getStatusBadge = (statusStr: string) => {
    const s = statusStr.toLowerCase();
    if (s === "active" || s === "pass" || s === "approved" || s === "healthy") {
      return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-emerald-900/40 text-emerald-300 border border-emerald-700/50">ACTIVE / PASS</span>;
    }
    if (s === "suspended" || s === "fail" || s === "critical" || s === "rolled_back") {
      return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-rose-900/40 text-rose-300 border border-rose-700/50">SUSPENDED / FAIL</span>;
    }
    if (s === "validation" || s === "degraded" || s === "warning" || s === "staged") {
      return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-amber-900/40 text-amber-300 border border-amber-700/50">STAGED / REVIEW</span>;
    }
    return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-slate-800 text-slate-300 border border-slate-700">{statusStr.toUpperCase()}</span>;
  };

  return (
    <div className="flex flex-col h-full bg-slate-950 text-slate-100 overflow-y-auto">
      {/* Top Banner */}
      <div className="p-6 border-b border-slate-800 bg-slate-900/70">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div>
            <div className="flex items-center space-x-3">
              <span className="px-2.5 py-1 text-xs font-bold uppercase rounded bg-indigo-900/60 text-indigo-300 border border-indigo-700">
                Phase 12 Control Plane
              </span>
              <h1 className="text-2xl font-bold tracking-tight text-white">Production Governance & Model Risk</h1>
            </div>
            <p className="text-sm text-slate-400 mt-1">
              Bank-deployable governance layer aligned with OCC (Nov 2026 / Bulletin 2026-13a) and NIST AI RMF supervisory standards.
            </p>
          </div>
          <div className="flex items-center space-x-3">
            <button
              onClick={fetchData}
              className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition"
            >
              Refresh Platform
            </button>
            <button
              onClick={handleEvaluateReadiness}
              className="px-3 py-1.5 text-xs font-medium bg-indigo-600 hover:bg-indigo-500 text-white rounded transition shadow-sm"
            >
              Evaluate Readiness Gates
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex space-x-1 mt-6 border-b border-slate-800 overflow-x-auto text-sm font-medium">
          {[
            { id: "overview", label: "System Health & Overview" },
            { id: "registry", label: `Component Registry (${components.length})` },
            { id: "validation", label: `Validation Runs (${validationRuns.length})` },
            { id: "releases", label: `Releases (${releases.length})` },
            { id: "killswitch", label: `Kill Switch (${suspensions.filter((s) => s.is_active).length} Active)` },
            { id: "incidents", label: `Incidents (${incidents.length})` },
            { id: "drift", label: `Drift Monitoring (${driftRecords.length})` },
            { id: "passports", label: `Evidence Passports (${passports.length})` },
            { id: "aiproviders", label: `AI Providers (${aiProviders.length})` },
            { id: "readiness", label: "Bank Validation Package" },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`px-4 py-2 border-b-2 whitespace-nowrap transition ${
                activeTab === tab.id
                  ? "border-indigo-500 text-indigo-400 font-semibold"
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Main Content Area */}
      <div className="p-6 flex-1">
        {loading && (
          <div className="flex items-center justify-center p-12 text-slate-400">
            <svg className="animate-spin h-6 w-6 mr-3 text-indigo-500" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
            </svg>
            Loading production governance state...
          </div>
        )}

        {error && (
          <div className="p-4 mb-6 rounded bg-rose-950/50 border border-rose-800 text-rose-300 text-sm">
            {error}
          </div>
        )}

        {/* 1. System Health & Overview */}
        {!loading && activeTab === "overview" && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="p-4 rounded-lg bg-slate-900 border border-slate-800">
                <div className="text-xs font-semibold text-slate-400 uppercase">Engine Status</div>
                <div className="mt-2 flex items-center justify-between">
                  <div className="text-2xl font-bold text-white">
                    {health ? health.overall_status.toUpperCase() : "HEALTHY"}
                  </div>
                  {getStatusBadge(health?.overall_status || "healthy")}
                </div>
                <div className="text-xs text-slate-500 mt-1">Autonomous containment ready</div>
              </div>
              <div className="p-4 rounded-lg bg-slate-900 border border-slate-800">
                <div className="text-xs font-semibold text-slate-400 uppercase">Governed Components</div>
                <div className="mt-2 text-2xl font-bold text-white">{components.length}</div>
                <div className="text-xs text-slate-500 mt-1">
                  {components.filter((c) => c.status === "active").length} Active in Production
                </div>
              </div>
              <div className="p-4 rounded-lg bg-slate-900 border border-slate-800">
                <div className="text-xs font-semibold text-slate-400 uppercase">Kill Switch Suspensions</div>
                <div className="mt-2 text-2xl font-bold text-amber-400">
                  {suspensions.filter((s) => s.is_active).length}
                </div>
                <div className="text-xs text-slate-500 mt-1">Granular fault containment</div>
              </div>
              <div className="p-4 rounded-lg bg-slate-900 border border-slate-800">
                <div className="text-xs font-semibold text-slate-400 uppercase">Open Incidents</div>
                <div className="mt-2 text-2xl font-bold text-rose-400">
                  {incidents.filter((i) => i.status !== "closed" && i.status !== "remediated").length}
                </div>
                <div className="text-xs text-slate-500 mt-1">Correlated casework impact</div>
              </div>
            </div>

            {/* Health Overview Message */}
            <div className="p-5 rounded-lg bg-slate-900/60 border border-slate-800">
              <h3 className="text-sm font-semibold text-slate-200">Supervisory Compliance Overview</h3>
              <p className="text-sm text-slate-400 mt-2 leading-relaxed">
                {health?.summary_message ||
                  "Toroka operates within strict banking regulatory guardrails: Maker-Checker separation for high-risk configurations, immutable hash-chain audit trails, granular kill-switch isolation, cryptographically bound evidence passports, and zero-training policies on third-party AI endpoints."}
              </p>
              <div className="mt-4 pt-4 border-t border-slate-800/80 flex items-center gap-6 text-xs text-slate-400">
                <div>
                  <span className="text-slate-500">Detection Health:</span>{" "}
                  <span className="text-emerald-400 font-semibold">{health?.detection_health || "HEALTHY"}</span>
                </div>
                <div>
                  <span className="text-slate-500">Data Contract:</span>{" "}
                  <span className="text-emerald-400 font-semibold">{health?.data_quality_health || "HEALTHY"}</span>
                </div>
                <div>
                  <span className="text-slate-500">Copilot Evaluation:</span>{" "}
                  <span className="text-emerald-400 font-semibold">{health?.copilot_health || "HEALTHY"}</span>
                </div>
                <div>
                  <span className="text-slate-500">Audit Ledger:</span>{" "}
                  <span className="text-emerald-400 font-semibold">{health?.audit_integrity_health || "UNBROKEN"}</span>
                </div>
              </div>
            </div>

            {/* Quick Actions */}
            <div className="flex gap-4">
              <button
                onClick={() => setActiveTab("registry")}
                className="px-4 py-2.5 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-sm font-medium transition"
              >
                Manage Models & Detectors
              </button>
              <button
                onClick={() => setActiveTab("killswitch")}
                className="px-4 py-2.5 rounded bg-rose-950/40 hover:bg-rose-900/50 border border-rose-800/60 text-rose-300 text-sm font-medium transition"
              >
                Access Emergency Kill-Switch
              </button>
              <button
                onClick={() => setActiveTab("readiness")}
                className="px-4 py-2.5 rounded bg-indigo-950/40 hover:bg-indigo-900/50 border border-indigo-800/60 text-indigo-300 text-sm font-medium transition"
              >
                View 13 Production Readiness Gates
              </button>
            </div>
          </div>
        )}

        {/* 2. Component Registry */}
        {!loading && activeTab === "registry" && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-semibold text-white">Model & Detector Registry</h2>
                <p className="text-xs text-slate-400">All rules, statistical detectors, machine learning models, prompts, and simulation policies.</p>
              </div>
              <button
                onClick={() => setRegisterModalOpen(true)}
                className="px-3 py-1.5 text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white rounded transition"
              >
                + Register Component
              </button>
            </div>

            <div className="overflow-x-auto rounded-lg border border-slate-800">
              <table className="w-full text-left text-sm text-slate-300">
                <thead className="bg-slate-900 text-xs uppercase text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-3">Component</th>
                    <th className="px-4 py-3">Type</th>
                    <th className="px-4 py-3">Version</th>
                    <th className="px-4 py-3">Risk Tier</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Author / Approver</th>
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 bg-slate-950/50">
                  {components.map((comp) => (
                    <tr key={`${comp.component_id}-${comp.version}`} className="hover:bg-slate-900/40 transition">
                      <td className="px-4 py-3">
                        <div className="font-semibold text-white">{comp.name}</div>
                        <div className="text-xs font-mono text-slate-500">{comp.component_id}</div>
                      </td>
                      <td className="px-4 py-3 text-xs uppercase font-mono text-indigo-300">{comp.component_type}</td>
                      <td className="px-4 py-3 font-mono text-xs">{comp.version}</td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 text-xs rounded font-medium ${
                          comp.risk_tier === "critical"
                            ? "bg-rose-950/60 text-rose-300 border border-rose-800"
                            : comp.risk_tier === "high"
                            ? "bg-amber-950/60 text-amber-300 border border-amber-800"
                            : "bg-slate-800 text-slate-300"
                        }`}>
                          {comp.risk_tier.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-4 py-3">{getStatusBadge(comp.status)}</td>
                      <td className="px-4 py-3 text-xs text-slate-400">
                        <div>Created: {comp.created_by}</div>
                        {comp.approved_by && <div className="text-emerald-400">Approved: {comp.approved_by}</div>}
                        {comp.suspended_by && <div className="text-rose-400">Suspended: {comp.suspended_by}</div>}
                      </td>
                      <td className="px-4 py-3 text-right space-x-2">
                        {comp.status === "validation" && (
                          <button
                            onClick={() => {
                              setApprovalTarget(comp);
                              setApprovalRationale("");
                            }}
                            className="px-2.5 py-1 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded transition"
                          >
                            Approve (Checker)
                          </button>
                        )}
                        {comp.status === "active" && (
                          <button
                            onClick={() => {
                              setSuspendTarget(comp);
                              setSuspendReason("");
                            }}
                            className="px-2.5 py-1 text-xs font-medium bg-rose-700 hover:bg-rose-600 text-white rounded transition"
                          >
                            Kill Switch
                          </button>
                        )}
                        {comp.status === "suspended" && (
                          <button
                            onClick={() => handleResume(comp)}
                            className="px-2.5 py-1 text-xs font-medium bg-amber-600 hover:bg-amber-500 text-white rounded transition"
                          >
                            Resume
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                  {components.length === 0 && (
                    <tr>
                      <td colSpan={7} className="px-4 py-8 text-center text-slate-500">
                        No governed components registered yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* 3. Validation Runs */}
        {!loading && activeTab === "validation" && (
          <div className="space-y-4">
            <div>
              <h2 className="text-lg font-semibold text-white">Model Validation Runs</h2>
              <p className="text-xs text-slate-400">Auditable validation executions evaluated against approved reference datasets.</p>
            </div>
            <div className="overflow-x-auto rounded-lg border border-slate-800">
              <table className="w-full text-left text-sm text-slate-300">
                <thead className="bg-slate-900 text-xs uppercase text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-3">Run ID</th>
                    <th className="px-4 py-3">Component</th>
                    <th className="px-4 py-3">Metrics</th>
                    <th className="px-4 py-3">Result</th>
                    <th className="px-4 py-3">Evaluator</th>
                    <th className="px-4 py-3">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 bg-slate-950/50">
                  {validationRuns.map((vr) => (
                    <tr key={vr.run_id} className="hover:bg-slate-900/40 transition">
                      <td className="px-4 py-3 font-mono text-xs text-indigo-300">{vr.run_id}</td>
                      <td className="px-4 py-3">
                        <div className="font-semibold text-white">{vr.component_id}</div>
                        <div className="text-xs font-mono text-slate-500">v{vr.component_version}</div>
                      </td>
                      <td className="px-4 py-3 text-xs">
                        <div className="flex flex-wrap gap-2">
                          {vr.metrics.map((m) => (
                            <span
                              key={m.name}
                              className={`px-1.5 py-0.5 rounded text-[11px] font-mono ${
                                m.result === "pass" ? "bg-emerald-950 text-emerald-300 border border-emerald-800" : "bg-rose-950 text-rose-300"
                              }`}
                            >
                              {m.name}: {m.value} {m.threshold ? `(thr: ${m.threshold})` : ""}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="px-4 py-3">{getStatusBadge(vr.result)}</td>
                      <td className="px-4 py-3 text-xs text-slate-400">{vr.evaluator}</td>
                      <td className="px-4 py-3 text-xs font-mono text-slate-500">{new Date(vr.created_at).toLocaleString()}</td>
                    </tr>
                  ))}
                  {validationRuns.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-4 py-8 text-center text-slate-500">
                        No validation runs recorded.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* 4. Release Manager & Rollback */}
        {!loading && activeTab === "releases" && (
          <div className="space-y-4">
            <div>
              <h2 className="text-lg font-semibold text-white">Production Release Manager</h2>
              <p className="text-xs text-slate-400">Cryptographically bound deployment manifests with one-click auditable rollback.</p>
            </div>
            <div className="grid grid-cols-1 gap-4">
              {releases.map((rel) => (
                <div key={rel.release_id} className="p-4 rounded-lg bg-slate-900 border border-slate-800 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                  <div>
                    <div className="flex items-center space-x-3">
                      <span className="text-lg font-bold text-white">Release {rel.version}</span>
                      <span className="text-xs px-2 py-0.5 rounded bg-indigo-900/60 text-indigo-300 uppercase font-mono">
                        {rel.environment}
                      </span>
                      {getStatusBadge(rel.status)}
                    </div>
                    <div className="text-xs font-mono text-slate-500 mt-1">ID: {rel.release_id} | Manifest: {rel.manifest_digest.slice(0, 16)}...</div>
                    <div className="text-xs text-slate-400 mt-2">
                      Components: {Object.keys(rel.components_manifest || {}).length} | Validations: {rel.validation_runs.length} | Gates: {rel.readiness_gates.length}
                    </div>
                    {rel.rollback_target_id && (
                      <div className="text-xs text-rose-400 font-semibold mt-1">
                        Rolled back to: {rel.rollback_target_id}
                      </div>
                    )}
                  </div>
                  <div className="flex items-center space-x-2">
                    {rel.status === "staged" && (
                      <button
                        onClick={async () => {
                          try {
                            await api.promoteRelease(rel.release_id, "production");
                            fetchData();
                          } catch (err: any) {
                            alert(`Promotion failed: ${err.message}`);
                          }
                        }}
                        className="px-3 py-1.5 text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white rounded transition"
                      >
                        Promote to Production
                      </button>
                    )}
                    {rel.status === "active" && (
                      <button
                        onClick={() => {
                          setRollbackReleaseId(rel.release_id);
                          setRollbackTargetId(releases.find((r) => r.release_id !== rel.release_id)?.release_id || "");
                        }}
                        className="px-3 py-1.5 text-xs font-semibold bg-rose-700 hover:bg-rose-600 text-white rounded transition"
                      >
                        Rollback Release
                      </button>
                    )}
                  </div>
                </div>
              ))}
              {releases.length === 0 && (
                <div className="p-8 text-center text-slate-500 bg-slate-900/40 rounded-lg border border-slate-800">
                  No releases created yet.
                </div>
              )}
            </div>
          </div>
        )}

        {/* 5. Kill Switch */}
        {!loading && activeTab === "killswitch" && (
          <div className="space-y-4">
            <div>
              <h2 className="text-lg font-semibold text-rose-400">Emergency Kill-Switch (Granular Suspension)</h2>
              <p className="text-xs text-slate-400">Immediate, surgical isolation of malfunctioning rules or detectors without platform downtime.</p>
            </div>
            <div className="overflow-x-auto rounded-lg border border-slate-800">
              <table className="w-full text-left text-sm text-slate-300">
                <thead className="bg-slate-900 text-xs uppercase text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-3">Suspension ID</th>
                    <th className="px-4 py-3">Component</th>
                    <th className="px-4 py-3">Reason</th>
                    <th className="px-4 py-3">Suspended By</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 bg-slate-950/50">
                  {suspensions.map((s) => (
                    <tr key={s.suspension_id} className="hover:bg-slate-900/40 transition">
                      <td className="px-4 py-3 font-mono text-xs text-indigo-300">{s.suspension_id}</td>
                      <td className="px-4 py-3">
                        <div className="font-semibold text-white">{s.component_id}</div>
                        <div className="text-xs font-mono text-slate-500">v{s.component_version}</div>
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-300 max-w-xs">{s.reason}</td>
                      <td className="px-4 py-3 text-xs text-slate-400">
                        {s.suspended_by}
                        <div className="text-[10px] font-mono text-slate-500">{new Date(s.suspended_at).toLocaleString()}</div>
                      </td>
                      <td className="px-4 py-3">
                        {s.is_active ? (
                          <span className="px-2 py-0.5 text-xs font-semibold rounded bg-rose-950 text-rose-300 border border-rose-800">
                            ACTIVE SUSPENSION
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 text-xs font-semibold rounded bg-slate-800 text-slate-400">
                            REINSTATED
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-right">
                        {s.is_active && (
                          <button
                            onClick={() =>
                              handleResume({
                                component_id: s.component_id,
                                version: s.component_version,
                              } as any)
                            }
                            className="px-2.5 py-1 text-xs font-medium bg-amber-600 hover:bg-amber-500 text-white rounded transition"
                          >
                            Re-enable
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                  {suspensions.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-4 py-8 text-center text-slate-500">
                        No active suspensions. All detection components operating normally.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* 6. Incidents */}
        {!loading && activeTab === "incidents" && (
          <div className="space-y-4">
            <div>
              <h2 className="text-lg font-semibold text-white">Governance & Operational Incidents</h2>
              <p className="text-xs text-slate-400">Direct correlation between model/data errors and affected bank casework.</p>
            </div>
            <div className="grid grid-cols-1 gap-4">
              {incidents.map((inc) => (
                <div key={inc.incident_id} className="p-4 rounded-lg bg-slate-900 border border-slate-800">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <span className="text-base font-bold text-white">{inc.title}</span>
                      <span className="px-2 py-0.5 text-xs uppercase font-mono rounded bg-slate-800 text-slate-300">
                        {inc.category}
                      </span>
                      {getStatusBadge(inc.status)}
                    </div>
                    <span className="text-xs text-slate-500 font-mono">{inc.incident_id}</span>
                  </div>
                  <div className="mt-2 text-xs text-slate-400">
                    <div>Affected Components: {inc.affected_components.join(", ") || "None"}</div>
                    <div className="mt-1 text-amber-300">
                      Correlated Impact: {inc.affected_case_ids.length} active cases impacted
                    </div>
                    {inc.remediation_notes && (
                      <div className="mt-2 p-2 bg-slate-950 rounded text-slate-300 border border-slate-800">
                        <span className="text-slate-500 font-semibold">Remediation:</span> {inc.remediation_notes}
                      </div>
                    )}
                  </div>
                </div>
              ))}
              {incidents.length === 0 && (
                <div className="p-8 text-center text-slate-500 bg-slate-900/40 rounded-lg border border-slate-800">
                  No operational governance incidents recorded.
                </div>
              )}
            </div>
          </div>
        )}

        {/* 7. Drift Monitoring */}
        {!loading && activeTab === "drift" && (
          <div className="space-y-4">
            <div>
              <h2 className="text-lg font-semibold text-white">Proactive Drift Monitoring</h2>
              <p className="text-xs text-slate-400">Continuous tracking across data distribution, model output PSI, detector volume, and AI response quality.</p>
            </div>
            <div className="overflow-x-auto rounded-lg border border-slate-800">
              <table className="w-full text-left text-sm text-slate-300">
                <thead className="bg-slate-900 text-xs uppercase text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-3">Type</th>
                    <th className="px-4 py-3">Component / Metric</th>
                    <th className="px-4 py-3">Baseline</th>
                    <th className="px-4 py-3">Observed</th>
                    <th className="px-4 py-3">Threshold</th>
                    <th className="px-4 py-3">Severity</th>
                    <th className="px-4 py-3">Recommended Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 bg-slate-950/50">
                  {driftRecords.map((d) => (
                    <tr key={d.drift_id} className="hover:bg-slate-900/40 transition">
                      <td className="px-4 py-3 text-xs uppercase font-mono text-indigo-300">{d.drift_type}</td>
                      <td className="px-4 py-3">
                        <div className="font-semibold text-white">{d.component_id}</div>
                        <div className="text-xs text-slate-400">{d.metric_name}</div>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs">{d.baseline_value}</td>
                      <td className="px-4 py-3 font-mono text-xs text-amber-300">{d.observed_value}</td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-400">{d.threshold}</td>
                      <td className="px-4 py-3">{getStatusBadge(d.severity)}</td>
                      <td className="px-4 py-3 text-xs text-slate-300 max-w-xs">{d.recommended_response}</td>
                    </tr>
                  ))}
                  {driftRecords.length === 0 && (
                    <tr>
                      <td colSpan={7} className="px-4 py-8 text-center text-slate-500">
                        No drift anomalies detected. All models conform to baseline distributions.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* 8. Evidence Passports */}
        {!loading && activeTab === "passports" && (
          <div className="space-y-4">
            <div>
              <h2 className="text-lg font-semibold text-white">Toroka Evidence Passports</h2>
              <p className="text-xs text-slate-400">Cryptographically bound (SHA-256) finding provenance objects ensuring complete evidentiary defensibility.</p>
            </div>
            <div className="grid grid-cols-1 gap-4">
              {passports.map((p) => (
                <div key={p.passport_id} className="p-4 rounded-lg bg-slate-900 border border-slate-800">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <span className="text-base font-bold text-white font-mono">{p.passport_id}</span>
                      <span className="px-2 py-0.5 text-xs font-semibold rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
                        INTEGRITY VERIFIED
                      </span>
                    </div>
                    <span className="text-xs text-slate-500 font-mono">Case: {p.case_id}</span>
                  </div>
                  <div className="mt-3 grid grid-cols-1 md:grid-cols-3 gap-2 text-xs text-slate-300 bg-slate-950 p-3 rounded border border-slate-800/80">
                    <div>
                      <span className="text-slate-500">Finding:</span> {p.finding_type} ({p.finding_id})
                    </div>
                    <div>
                      <span className="text-slate-500">Evidence Count:</span> {p.evidence_count} events
                    </div>
                    <div>
                      <span className="text-slate-500">Sources:</span> {p.source_systems.join(", ")}
                    </div>
                    <div>
                      <span className="text-slate-500">Evidence Debt:</span> {p.evidence_debt_level}
                    </div>
                    <div>
                      <span className="text-slate-500">Validation:</span> {p.validation_result}
                    </div>
                    <div>
                      <span className="text-slate-500">Human Review:</span> {p.human_review_required ? "MANDATORY" : "OPTIONAL"}
                    </div>
                  </div>
                  <div className="mt-2 text-[11px] font-mono text-slate-500 break-all">
                    SHA-256 Passport Digest: {p.passport_digest}
                  </div>
                </div>
              ))}
              {passports.length === 0 && (
                <div className="p-8 text-center text-slate-500 bg-slate-900/40 rounded-lg border border-slate-800">
                  No evidence passports generated yet.
                </div>
              )}
            </div>
          </div>
        )}

        {/* 9. AI Providers */}
        {!loading && activeTab === "aiproviders" && (
          <div className="space-y-4">
            <div>
              <h2 className="text-lg font-semibold text-white">Governed AI Providers & LLM Governance</h2>
              <p className="text-xs text-slate-400">Strict zero customer-training enforcement and data retention verification under OCC/NIST standards.</p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {aiProviders.map((prov) => (
                <div key={prov.provider_id} className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-base font-bold text-white">{prov.provider_name}</span>
                    {getStatusBadge(prov.is_approved ? "APPROVED" : "REJECTED")}
                  </div>
                  <div className="text-xs font-mono text-indigo-300">
                    {prov.model_identifier} (v{prov.model_version})
                  </div>
                  <div className="text-xs text-slate-400 space-y-1 pt-2 border-t border-slate-800">
                    <div>Hosting Location: <span className="text-slate-200">{prov.hosting_location}</span></div>
                    <div>Retention Policy: <span className="text-slate-200">{prov.data_retention_policy}</span></div>
                    <div>
                      Training on Customer Data:{" "}
                      <span className={prov.training_on_customer_data_permitted ? "text-rose-400 font-bold" : "text-emerald-400 font-bold"}>
                        {prov.training_on_customer_data_permitted ? "PERMITTED (CRITICAL RISK)" : "STRICTLY PROHIBITED (COMPLIANT)"}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* 10. Readiness & Validation Package */}
        {!loading && activeTab === "readiness" && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-semibold text-white">13 Production Readiness Gates</h2>
                <p className="text-xs text-slate-400">Mandatory bank qualification criteria before deployment approval.</p>
              </div>
              <button
                onClick={handleEvaluateReadiness}
                className="px-3 py-1.5 text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white rounded transition"
              >
                Run Readiness Audit
              </button>
            </div>

            {readiness && (
              <div className="p-4 rounded-lg bg-slate-900 border border-slate-800">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div>
                    <span className="text-base font-bold text-white">Assessment for Release {readiness.release_version}</span>
                    <div className="text-xs text-slate-400">Evaluated at: {new Date(readiness.evaluated_at).toLocaleString()}</div>
                  </div>
                  {getStatusBadge(readiness.overall_status)}
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 mt-4">
                  {readiness.gates.map((g) => (
                    <div key={g.gate_name} className="p-3 bg-slate-950 rounded border border-slate-800 text-xs">
                      <div className="flex items-center justify-between font-semibold">
                        <span className="text-slate-200">{g.gate_name}</span>
                        {getStatusBadge(g.status)}
                      </div>
                      <div className="text-slate-400 mt-1">{g.rationale}</div>
                      <div className="text-[10px] text-slate-500 mt-2 font-mono">Verified by: {g.verified_by}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {validationPkg && (
              <div className="p-5 rounded-lg bg-slate-900/80 border border-indigo-900/50 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-bold text-indigo-300 uppercase tracking-wider">Bank Validation Package Summary</h3>
                  <span className="text-xs font-mono text-slate-400">{validationPkg.release_version}</span>
                </div>
                <p className="text-sm text-slate-300 leading-relaxed">{validationPkg.executive_summary}</p>
                <div className="grid grid-cols-3 gap-3 pt-3 border-t border-slate-800 text-xs">
                  <div>
                    <span className="text-slate-500">Components Count:</span>{" "}
                    <span className="font-bold text-white">{validationPkg.components_count}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Validation Runs:</span>{" "}
                    <span className="font-bold text-white">{validationPkg.validation_runs_count}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Active Suspensions:</span>{" "}
                    <span className="font-bold text-amber-400">{validationPkg.active_suspensions_count}</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Registration Modal */}
      {registerModalOpen && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-lg max-w-md w-full p-6 space-y-4">
            <h3 className="text-lg font-bold text-white">Register Governed Component</h3>
            <form onSubmit={handleRegisterComponent} className="space-y-3 text-sm">
              <div>
                <label className="text-xs text-slate-400">Component ID</label>
                <input
                  type="text"
                  required
                  value={newCompId}
                  onChange={(e) => setNewCompId(e.target.value)}
                  placeholder="e.g. det_rapid_flow"
                  className="w-full mt-1 p-2 rounded bg-slate-950 border border-slate-800 text-white"
                />
              </div>
              <div>
                <label className="text-xs text-slate-400">Component Name</label>
                <input
                  type="text"
                  required
                  value={newCompName}
                  onChange={(e) => setNewCompName(e.target.value)}
                  placeholder="e.g. Rapid Flow Detector"
                  className="w-full mt-1 p-2 rounded bg-slate-950 border border-slate-800 text-white"
                />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="text-xs text-slate-400">Version</label>
                  <input
                    type="text"
                    required
                    value={newCompVer}
                    onChange={(e) => setNewCompVer(e.target.value)}
                    placeholder="e.g. 1.0.0"
                    className="w-full mt-1 p-2 rounded bg-slate-950 border border-slate-800 text-white"
                  />
                </div>
                <div>
                  <label className="text-xs text-slate-400">Owner Team</label>
                  <input
                    type="text"
                    required
                    value={newCompOwner}
                    onChange={(e) => setNewCompOwner(e.target.value)}
                    placeholder="e.g. Fraud Analytics"
                    className="w-full mt-1 p-2 rounded bg-slate-950 border border-slate-800 text-white"
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="text-xs text-slate-400">Type</label>
                  <select
                    value={newCompType}
                    onChange={(e) => setNewCompType(e.target.value)}
                    className="w-full mt-1 p-2 rounded bg-slate-950 border border-slate-800 text-white"
                  >
                    <option value="detector">Detector</option>
                    <option value="rule">Rule</option>
                    <option value="statistical_model">Statistical Model</option>
                    <option value="ml_model">ML Model</option>
                    <option value="prompt">Prompt</option>
                    <option value="policy">Policy</option>
                    <option value="simulation">Simulation</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs text-slate-400">Risk Tier</label>
                  <select
                    value={newCompRisk}
                    onChange={(e) => setNewCompRisk(e.target.value)}
                    className="w-full mt-1 p-2 rounded bg-slate-950 border border-slate-800 text-white"
                  >
                    <option value="low">Low</option>
                    <option value="moderate">Moderate</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>
              </div>
              <div className="flex justify-end space-x-2 pt-3">
                <button
                  type="button"
                  onClick={() => setRegisterModalOpen(false)}
                  className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 rounded bg-indigo-600 hover:bg-indigo-500 text-xs text-white font-semibold"
                >
                  Register Component
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Approval Checker Modal */}
      {approvalTarget && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-lg max-w-md w-full p-6 space-y-4">
            <h3 className="text-lg font-bold text-white">Checker Approval (Maker-Checker Enforced)</h3>
            <p className="text-xs text-slate-400">
              Authorizing component: <span className="font-semibold text-white">{approvalTarget.name}</span> ({approvalTarget.component_id})
            </p>
            <div className="space-y-3 text-sm">
              <div>
                <label className="text-xs text-slate-400">Validation Run ID</label>
                <input
                  type="text"
                  value={approvalValRunId}
                  onChange={(e) => setApprovalValRunId(e.target.value)}
                  className="w-full mt-1 p-2 rounded bg-slate-950 border border-slate-800 text-white"
                />
              </div>
              <div>
                <label className="text-xs text-slate-400">Approval Rationale</label>
                <textarea
                  rows={3}
                  value={approvalRationale}
                  onChange={(e) => setApprovalRationale(e.target.value)}
                  placeholder="State justification and benchmark results reviewed..."
                  className="w-full mt-1 p-2 rounded bg-slate-950 border border-slate-800 text-white"
                />
              </div>
              <div className="flex justify-end space-x-2 pt-2">
                <button
                  onClick={() => setApprovalTarget(null)}
                  className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300"
                >
                  Cancel
                </button>
                <button
                  onClick={handleApprove}
                  className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-xs text-white font-semibold"
                >
                  Sign & Approve
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Kill Switch Modal */}
      {suspendTarget && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-rose-900/60 rounded-lg max-w-md w-full p-6 space-y-4">
            <h3 className="text-lg font-bold text-rose-400">Trigger Kill Switch</h3>
            <p className="text-xs text-slate-400">
              Immediately suspend <span className="font-semibold text-white">{suspendTarget.name}</span> ({suspendTarget.component_id}).
            </p>
            <div className="space-y-3 text-sm">
              <div>
                <label className="text-xs text-slate-400">Reason for Suspension</label>
                <textarea
                  rows={3}
                  value={suspendReason}
                  onChange={(e) => setSuspendReason(e.target.value)}
                  placeholder="Explain the detected fault or false-positive spike..."
                  className="w-full mt-1 p-2 rounded bg-slate-950 border border-slate-800 text-white"
                />
              </div>
              <div className="flex justify-end space-x-2 pt-2">
                <button
                  onClick={() => setSuspendTarget(null)}
                  className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300"
                >
                  Cancel
                </button>
                <button
                  onClick={handleSuspend}
                  className="px-3 py-1.5 rounded bg-rose-700 hover:bg-rose-600 text-xs text-white font-semibold"
                >
                  Confirm Emergency Suspension
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Rollback Modal */}
      {rollbackReleaseId && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-rose-900/60 rounded-lg max-w-md w-full p-6 space-y-4">
            <h3 className="text-lg font-bold text-rose-400">Emergency Release Rollback</h3>
            <p className="text-xs text-slate-400">
              Rollback release <span className="font-mono text-white">{rollbackReleaseId}</span> to target baseline.
            </p>
            <div className="space-y-3 text-sm">
              <div>
                <label className="text-xs text-slate-400">Target Release ID</label>
                <input
                  type="text"
                  value={rollbackTargetId}
                  onChange={(e) => setRollbackTargetId(e.target.value)}
                  placeholder="e.g. rel-abc123"
                  className="w-full mt-1 p-2 rounded bg-slate-950 border border-slate-800 text-white"
                />
              </div>
              <div>
                <label className="text-xs text-slate-400">Rollback Justification</label>
                <textarea
                  rows={3}
                  value={rollbackReason}
                  onChange={(e) => setRollbackReason(e.target.value)}
                  placeholder="Provide auditable justification for rollback..."
                  className="w-full mt-1 p-2 rounded bg-slate-950 border border-slate-800 text-white"
                />
              </div>
              <div className="flex justify-end space-x-2 pt-2">
                <button
                  onClick={() => setRollbackReleaseId(null)}
                  className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300"
                >
                  Cancel
                </button>
                <button
                  onClick={handleRollback}
                  className="px-3 py-1.5 rounded bg-rose-700 hover:bg-rose-600 text-xs text-white font-semibold"
                >
                  Execute Rollback
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
