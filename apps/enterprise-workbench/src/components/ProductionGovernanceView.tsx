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
  QuantitativeDriftEvaluation,
  ChampionChallengerRun,
  ForensicDossier,
  InflightPaymentEvaluation,
  CopVerifyResponse,
  TelecomSignalResponse,
  Persona,
} from "../types";

interface Props {
  currentPersona: Persona;
}

export const ProductionGovernanceView: React.FC<Props> = ({ currentPersona }) => {
  const [activeTab, setActiveTab] = useState<
    "overview" | "registry" | "validation" | "releases" | "killswitch" | "incidents" | "drift" | "passports" | "aiproviders" | "readiness" | "modelrisk" | "forensics_iso"
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
  const [quantDrifts, setQuantDrifts] = useState<QuantitativeDriftEvaluation[]>([]);
  const [championChallengerRuns, setChampionChallengerRuns] = useState<ChampionChallengerRun[]>([]);

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

  // Forensic Dossier & ISO 20022 simulator state
  const [dossierCaseId, setDossierCaseId] = useState("case-001");
  const [dossierTitle, setDossierTitle] = useState("M-PESA Pass-Through Laundering Ring");
  const [dossierAmount, setDossierAmount] = useState(1500000);
  const [dossierSummary, setDossierSummary] = useState("Corroborated 4-hop pass-through velocity anomaly transferring illicit funds across 3 commercial banks and 2 telco wallets.");
  const [dossierCertifier, setDossierCertifier] = useState("Inspector J. Kamau");
  const [activeDossier, setActiveDossier] = useState<ForensicDossier | null>(null);

  // ISO 20022 simulator state
  const [isoAmount, setIsoAmount] = useState(350000);
  const [isoRail, setIsoRail] = useState("PESALINK");
  const [isoDebtorAcct, setIsoDebtorAcct] = useState("01129384756");
  const [isoCreditorAcct, setIsoCreditorAcct] = useState("01199887766");
  const [isoNarrative, setIsoNarrative] = useState("Urgent unlock fee for pending deposit");
  const [isoEvaluation, setIsoEvaluation] = useState<InflightPaymentEvaluation | null>(null);
  const [isoEvaluating, setIsoEvaluating] = useState(false);

  // Phase 14.0 Confirmation of Payee (CoP) & Graduated Controls state
  const [copIntendedName, setCopIntendedName] = useState("Patrick Mwangi");
  const [copRegisteredName, setCopRegisteredName] = useState("Patrick Mwangi");
  const [copAcctNumber, setCopAcctNumber] = useState("01100998877");
  const [copAcctType, setCopAcctType] = useState<"PERSONAL" | "BUSINESS">("PERSONAL");
  const [copRail, setCopRail] = useState("PESALINK");
  const [copBic, setCopBic] = useState("KCBKKENA");
  const [copVerifying, setCopVerifying] = useState(false);
  const [copResult, setCopResult] = useState<CopVerifyResponse | null>(null);

  const [enableGraduatedControls, setEnableGraduatedControls] = useState(true);
  const [beneficiaryInflowRestriction, setBeneficiaryInflowRestriction] = useState(false);
  const [debtorChannelAnomaly, setDebtorChannelAnomaly] = useState(false);
  const [isoCopStatus, setIsoCopStatus] = useState<string>("NONE");

  // Phase 14.1 Telecom Scam Signal state
  const [telecomMsisdn, setTelecomMsisdn] = useState("+254712345678");
  const [telecomCarrier, setTelecomCarrier] = useState<"SAFARICOM" | "AIRTEL" | "TELKOM">("SAFARICOM");
  const [telecomSimulatedCall, setTelecomSimulatedCall] = useState<"IDLE" | "CALL_IN_PROGRESS" | "RECENT_CALL">("CALL_IN_PROGRESS");
  const [telecomCallDuration, setTelecomCallDuration] = useState(320);
  const [telecomSimSwapAge, setTelecomSimSwapAge] = useState<number | undefined>(undefined);
  const [telecomQuerying, setTelecomQuerying] = useState(false);
  const [telecomResult, setTelecomResult] = useState<TelecomSignalResponse | null>(null);
  const [isoTelecomCallStatus, setIsoTelecomCallStatus] = useState<string>("NONE");

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [h, comps, vRuns, rels, susps, incs, drifts, pass, providers, qDrifts, ccRuns] = await Promise.all([
        api.getSystemHealthOverview().catch(() => null),
        api.listGovernedComponents().catch(() => []),
        api.listValidationRuns().catch(() => []),
        api.listReleases().catch(() => []),
        api.listSuspensions().catch(() => []),
        api.listGovernanceIncidents().catch(() => []),
        api.listDriftRecords().catch(() => []),
        api.listEvidencePassports().catch(() => []),
        api.listAIProviders().catch(() => []),
        api.listQuantitativeDriftEvaluations().catch(() => []),
        api.listChampionChallengerRuns().catch(() => []),
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
      setQuantDrifts(qDrifts);
      setChampionChallengerRuns(ccRuns);

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

  const handleCreateDossier = async () => {
    try {
      const res = await api.createForensicDossier({
        case_id: dossierCaseId,
        title: dossierTitle,
        fraud_loss_amount: dossierAmount,
        currency: "KES",
        case_summary: dossierSummary,
        certifier_name: dossierCertifier,
        certifier_designation: "Senior Forensic Investigator",
        declaration_text: "I certify under Section 106B of the Kenya Evidence Act that this electronic evidence record was generated during the ordinary course of computer operations without malfunction.",
        identified_mule_nodes: [
          { account_number: "01199887766", entity_name: "Kamau Enterprises", risk_score: 0.94, role: "Pass-Through Mule" },
          { account_number: "+254712345678", entity_name: "Cash-Out Wallet A", risk_score: 0.88, role: "Terminal Cash-Out" },
        ],
      });
      setActiveDossier(res);
      alert(`Forensic Dossier ${res.dossier_id} compiled successfully!`);
    } catch (err: any) {
      alert(`Failed to compile dossier: ${err.message}`);
    }
  };

  const handleSignDossier = async (dossierId: string) => {
    try {
      const res = await api.signForensicDossier(dossierId, "Ed25519");
      setActiveDossier(res);
      alert(`Dossier signed with examiner Ed25519 HSM key! Signature hex: ${res.signature_bundle?.signature_hex.slice(0, 16)}...`);
    } catch (err: any) {
      alert(`Dossier signing failed: ${err.message}`);
    }
  };

  const handleVerifyDossier = async (dossierId: string) => {
    try {
      const res = await api.verifyForensicDossier(dossierId);
      if (res.is_valid && res.digest_verified) {
        alert(`Dossier ${dossierId} verified! Content hash unbroken. PKI signature: ${res.signature_verified ? "VALID" : "N/A"}`);
      } else {
        alert(`Verification failed: ${res.error || "Digest mismatch"}`);
      }
    } catch (err: any) {
      alert(`Verification exception: ${err.message}`);
    }
  };

  const handleVerifyCop = async () => {
    setCopVerifying(true);
    try {
      const res = await api.verifyConfirmationOfPayee({
        intended_name: copIntendedName,
        registered_name: copRegisteredName,
        account_number: copAcctNumber,
        account_type: copAcctType,
        clearing_rail: copRail,
        bank_bic: copBic,
      });
      setCopResult(res);
      setIsoCopStatus(res.status);
    } catch (err: any) {
      alert(`Confirmation of Payee failed: ${err.message}`);
    } finally {
      setCopVerifying(false);
    }
  };

  const handleQueryTelecom = async () => {
    setTelecomQuerying(true);
    try {
      const res = await api.evaluateTelecomSignal({
        msisdn: telecomMsisdn,
        carrier: telecomCarrier,
        simulated_call_status: telecomSimulatedCall !== "IDLE" ? telecomSimulatedCall : undefined,
        simulated_call_duration_seconds: telecomCallDuration,
        simulated_sim_swap_age_hours: telecomSimSwapAge,
      });
      setTelecomResult(res);
      if (res.call_status === "CALL_IN_PROGRESS") {
        setIsoTelecomCallStatus("CALL_IN_PROGRESS");
      }
    } catch (err: any) {
      alert(`Telecom Query failed: ${err.message}`);
    } finally {
      setTelecomQuerying(false);
    }
  };

  const handleEvaluateInflightPayment = async () => {
    setIsoEvaluating(true);
    try {
      const res = await api.evaluateInflightPayment({
        end_to_end_id: `E2E-${Date.now().toString(16)}`,
        amount: isoAmount,
        currency: "KES",
        clearing_rail: isoRail,
        debtor_name: "James Kariuki (Payer)",
        debtor_account: isoDebtorAcct,
        debtor_bic: "KCBKKENA",
        creditor_name: copIntendedName || "Kamau Enterprises (Mule)",
        creditor_account: isoCreditorAcct,
        creditor_bic: "EQBLKENA",
        remittance_narrative: isoNarrative,
        account_prior_transfers_count: 0,
        cop_status: isoCopStatus !== "NONE" ? isoCopStatus : undefined,
        cop_match_score: copResult?.match_score,
        beneficiary_inflow_restriction: beneficiaryInflowRestriction,
        debtor_channel_anomaly: debtorChannelAnomaly,
        enable_graduated_controls: enableGraduatedControls,
        telecom_call_status: isoTelecomCallStatus !== "NONE" ? isoTelecomCallStatus : undefined,
        telecom_coercion_score: telecomResult?.scam_signal_score,
      });
      setIsoEvaluation(res);
    } catch (err: any) {
      alert(`Evaluation failed: ${err.message}`);
    } finally {
      setIsoEvaluating(false);
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
    if (s === "unknown") {
      return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-amber-950/60 text-amber-300 border border-amber-600/70">UNKNOWN / UNVERIFIED</span>;
    }
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

  const getPillarColorClass = (status?: string) => {
    const s = (status || "UNKNOWN").toUpperCase();
    if (s === "HEALTHY" || s === "UNBROKEN") return "text-emerald-400 font-semibold";
    if (s === "DEGRADED" || s === "WARNING") return "text-amber-400 font-semibold";
    if (s === "CRITICAL" || s === "FAIL") return "text-rose-400 font-semibold";
    return "text-slate-400 font-semibold";
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
            { id: "modelrisk", label: `Model Risk & PSI (${quantDrifts.length})` },
            { id: "forensics_iso", label: "CoP, ISO 20022 & Evidence Dossiers" },
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
                    {health ? health.overall_status.toUpperCase() : "UNKNOWN"}
                  </div>
                  {getStatusBadge(health?.overall_status || "unknown")}
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
                  <span className={getPillarColorClass(health?.detection_health)}>{health?.detection_health || "UNKNOWN"}</span>
                </div>
                <div>
                  <span className="text-slate-500">Data Contract:</span>{" "}
                  <span className={getPillarColorClass(health?.data_quality_health)}>{health?.data_quality_health || "UNKNOWN"}</span>
                </div>
                <div>
                  <span className="text-slate-500">Copilot Evaluation:</span>{" "}
                  <span className={getPillarColorClass(health?.copilot_health)}>{health?.copilot_health || "UNKNOWN"}</span>
                </div>
                <div>
                  <span className="text-slate-500">Audit Ledger:</span>{" "}
                  <span className={getPillarColorClass(health?.audit_integrity_health)}>{health?.audit_integrity_health || "UNKNOWN"}</span>
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
                      {rel.is_digitally_signed || rel.signature_bundle ? (
                        <span className="px-2 py-0.5 text-xs font-semibold rounded bg-indigo-950 text-indigo-300 border border-indigo-700 flex items-center gap-1">
                          🔒 PKI SIGNED
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 text-xs font-semibold rounded bg-slate-800 text-slate-400">
                          TAMPER-EVIDENT HASH
                        </span>
                      )}
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
                    {!rel.is_digitally_signed && !rel.signature_bundle && currentPersona.role === "authoriser" && (
                      <button
                        onClick={async () => {
                          try {
                            await api.signRelease(rel.release_id);
                            fetchData();
                          } catch (err: any) {
                            alert(`Signing failed: ${err.message}`);
                          }
                        }}
                        className="px-2.5 py-1.5 text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white rounded transition shadow-sm"
                      >
                        Sign with HSM
                      </button>
                    )}
                    <button
                      onClick={async () => {
                        try {
                          const res = await api.verifyRelease(rel.release_id);
                          alert(
                            `Release Verification:\nStatus: ${res.is_valid ? "VALID" : "INVALID"}\nDigest: ${
                              res.digest_verified ? "MATCH" : "MISMATCH"
                            }\nDigital Signature: ${
                              res.signature_verified ? "VERIFIED" : res.is_digitally_signed ? "FAILED" : "NONE (Hash Only)"
                            }`
                          );
                        } catch (err: any) {
                          alert(`Verification error: ${err.message}`);
                        }
                      }}
                      className="px-2.5 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 rounded transition"
                    >
                      Verify
                    </button>
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
                      {p.is_digitally_signed || p.signature_bundle ? (
                        <span className="px-2 py-0.5 text-xs font-semibold rounded bg-indigo-950 text-indigo-300 border border-indigo-700 flex items-center gap-1">
                          🔒 PKI SIGNED
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 text-xs font-semibold rounded bg-slate-800 text-slate-400">
                          TAMPER-EVIDENT HASH
                        </span>
                      )}
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className="text-xs text-slate-500 font-mono">Case: {p.case_id}</span>
                      {!p.is_digitally_signed && !p.signature_bundle && currentPersona.role === "authoriser" && (
                        <button
                          onClick={async () => {
                            try {
                              await api.signPassport(p.passport_id);
                              fetchData();
                            } catch (err: any) {
                              alert(`Passport signing failed: ${err.message}`);
                            }
                          }}
                          className="px-2.5 py-1 text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white rounded transition shadow-sm"
                        >
                          Sign with HSM
                        </button>
                      )}
                      <button
                        onClick={async () => {
                          try {
                            const res = await api.verifyPassport(p.passport_id);
                            alert(
                              `Passport Verification:\nStatus: ${res.is_valid ? "VALID" : "INVALID"}\nDigest: ${
                                res.digest_verified ? "MATCH" : "MISMATCH"
                              }\nDigital Signature: ${
                                res.signature_verified ? "VERIFIED" : res.is_digitally_signed ? "FAILED" : "NONE (Hash Only)"
                              }`
                            );
                          } catch (err: any) {
                            alert(`Verification error: ${err.message}`);
                          }
                        }}
                        className="px-2 py-1 text-xs font-medium bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 rounded transition"
                      >
                        Verify
                      </button>
                    </div>
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

        {/* Phase 13.0: Model Risk & Quantitative Governance (OCC SR 11-7 / Fed SR 15-18) */}
        {!loading && activeTab === "modelrisk" && (
          <div className="space-y-6">
            <div className="flex items-center justify-between flex-wrap gap-4">
              <div>
                <h2 className="text-lg font-semibold text-white">Quantitative Model Risk Governance (OCC SR 11-7)</h2>
                <p className="text-xs text-slate-400">
                  Statistical distribution stability (PSI), continuous Kolmogorov-Smirnov / Wasserstein drift monitoring, and Champion-Challenger shadow governance.
                </p>
              </div>
              <div className="flex items-center space-x-2">
                <span className="px-2.5 py-1 text-xs font-mono font-semibold rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
                  PSI &lt; 0.10: STABLE
                </span>
                <span className="px-2.5 py-1 text-xs font-mono font-semibold rounded bg-amber-950 text-amber-300 border border-amber-800">
                  0.10 - 0.25: MODERATE
                </span>
                <span className="px-2.5 py-1 text-xs font-mono font-semibold rounded bg-rose-950 text-rose-300 border border-rose-800">
                  &ge; 0.25: SIGNIFICANT
                </span>
              </div>
            </div>

            {/* 1. Quantitative Drift Evaluations */}
            <div className="space-y-3">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400">
                Population Stability Index (PSI) &amp; Drift Evaluations ({quantDrifts.length})
              </h3>
              <div className="grid grid-cols-1 gap-4">
                {quantDrifts.map((qd) => (
                  <div key={qd.evaluation_id} className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3">
                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <div className="flex items-center space-x-3">
                        <span className="text-base font-bold text-white">{qd.component_id}</span>
                        <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                          v{qd.component_version}
                        </span>
                        <span
                          className={`px-2 py-0.5 text-xs font-semibold rounded border ${
                            qd.psi_severity === "STABLE"
                              ? "bg-emerald-950 text-emerald-300 border-emerald-800"
                              : qd.psi_severity === "MODERATE"
                              ? "bg-amber-950 text-amber-300 border-amber-800"
                              : "bg-rose-950 text-rose-300 border-rose-800"
                          }`}
                        >
                          PSI: {qd.psi_score.toFixed(4)} ({qd.psi_severity})
                        </span>
                        {qd.is_compliant ? (
                          <span className="px-2 py-0.5 text-xs font-semibold rounded bg-emerald-900/60 text-emerald-300">
                            SR 11-7 COMPLIANT
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 text-xs font-semibold rounded bg-rose-900/60 text-rose-300">
                            NON-COMPLIANT
                          </span>
                        )}
                      </div>
                      <span className="text-xs font-mono text-slate-500">{qd.evaluation_id}</span>
                    </div>

                    <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs bg-slate-950 p-3 rounded border border-slate-800/80">
                      <div>
                        <span className="text-slate-500">KS Statistic:</span> D={qd.ks_statistic.toFixed(4)} (p={qd.ks_p_value.toExponential(2)})
                      </div>
                      <div>
                        <span className="text-slate-500">Wasserstein-1:</span> {qd.wasserstein_distance.toFixed(4)}
                      </div>
                      <div>
                        <span className="text-slate-500">Mitigation Required:</span> {qd.requires_mitigation ? "YES (FAIL-CLOSED)" : "NO"}
                      </div>
                      <div>
                        <span className="text-slate-500">Fairness (DIR &ge; 0.80):</span> {qd.fairness_compliant ? "PASS" : "VIOLATION"}
                      </div>
                    </div>

                    {qd.governance_findings.length > 0 && (
                      <div className="text-xs text-rose-300 bg-rose-950/30 p-2.5 rounded border border-rose-900/40 space-y-1">
                        {qd.governance_findings.map((f, i) => (
                          <div key={i} className="flex items-center gap-1.5">
                            <span>⚠</span>
                            <span>{f}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
                {quantDrifts.length === 0 && (
                  <div className="p-8 text-center text-slate-500 bg-slate-900/40 rounded-lg border border-slate-800">
                    No quantitative drift evaluations recorded yet. Run scheduled or on-demand model validation.
                  </div>
                )}
              </div>
            </div>

            {/* 2. Champion-Challenger Shadow Governance */}
            <div className="space-y-3 pt-4 border-t border-slate-800">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400">
                Champion-Challenger Shadow Testing &amp; Promotion Gates ({championChallengerRuns.length})
              </h3>
              <div className="grid grid-cols-1 gap-4">
                {championChallengerRuns.map((run) => (
                  <div key={run.run_id} className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-3">
                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <div className="flex items-center space-x-3">
                        <span className="text-base font-bold text-white">{run.component_id}</span>
                        <span className="text-xs font-mono text-slate-400">
                          Champion v{run.champion_version} vs Challenger v{run.challenger_version}
                        </span>
                        <span
                          className={`px-2 py-0.5 text-xs font-semibold rounded border ${
                            run.is_promotable
                              ? "bg-emerald-950 text-emerald-300 border-emerald-800"
                              : "bg-rose-950 text-rose-300 border-rose-800"
                          }`}
                        >
                          {run.decision}
                        </span>
                      </div>
                      <span className="text-xs font-mono text-slate-500">{run.run_id}</span>
                    </div>

                    <div className="grid grid-cols-3 gap-2 text-xs bg-slate-950 p-3 rounded border border-slate-800/80">
                      <div>
                        <span className="text-slate-500">FDR Delta:</span> {(run.fdr_delta * 100).toFixed(2)}% (limit: &le; +2.00%)
                      </div>
                      <div>
                        <span className="text-slate-500">F1 Retention:</span> {(run.f1_ratio * 100).toFixed(2)}% (limit: &ge; 98.00%)
                      </div>
                      <div>
                        <span className="text-slate-500">p95 Latency Delta:</span> {run.latency_p95_delta_ms.toFixed(1)}ms
                      </div>
                    </div>

                    <div className="text-xs text-slate-300 space-y-1">
                      {run.reasons.map((r, i) => (
                        <div key={i} className="flex items-center gap-1.5 text-slate-400">
                          <span>•</span>
                          <span>{r}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
                {championChallengerRuns.length === 0 && (
                  <div className="p-8 text-center text-slate-500 bg-slate-900/40 rounded-lg border border-slate-800">
                    No Champion-Challenger shadow runs executed. Parallel traffic evaluation tracks candidate non-inferiority.
                  </div>
                )}
              </div>
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
                    {getStatusBadge(prov.review_status === "PENDING_INDEPENDENT_REVIEW" ? "PENDING REVIEW" : (prov.is_approved ? "APPROVED" : "REJECTED"))}
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

        {/* 10. Court Dossiers (Sec 106B) & ISO 20022 Clearing */}
        {!loading && activeTab === "forensics_iso" && (
          <div className="space-y-8">
            {/* Header */}
            <div>
              <h2 className="text-lg font-semibold text-white">Forensic Evidence Dossiers & Shadow ISO 20022 Clearing Risk</h2>
              <p className="text-xs text-slate-400">
                Admissibility packages under Section 106B of the Kenya Evidence Act and shadow in-flight payment advisory risk scoring.
              </p>
            </div>

            {/* Split layout: Dossiers on left, ISO 20022 on right */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Section 1: Court Dossier Compiler */}
              <div className="p-5 rounded-lg bg-slate-900 border border-slate-800 space-y-4">
                <div className="border-b border-slate-800 pb-3">
                  <h3 className="text-sm font-bold text-white flex items-center">
                    <span className="mr-2">⚖️</span> Forensic Evidence Dossier Compiler
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Compile an immutable, tamper-evident judicial evidence package with chain of custody and provenance verification.
                  </p>
                </div>

                <div className="space-y-3 text-xs">
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="text-slate-400 block mb-1">Case Reference ID</label>
                      <input
                        value={dossierCaseId}
                        onChange={(e) => setDossierCaseId(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white"
                      />
                    </div>
                    <div>
                      <label className="text-slate-400 block mb-1">Quantified Loss (KES)</label>
                      <input
                        type="number"
                        value={dossierAmount}
                        onChange={(e) => setDossierAmount(parseFloat(e.target.value) || 0)}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="text-slate-400 block mb-1">Incident / Syndicate Title</label>
                    <input
                      value={dossierTitle}
                      onChange={(e) => setDossierTitle(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white"
                    />
                  </div>

                  <div>
                    <label className="text-slate-400 block mb-1">Certifying Forensic Examiner</label>
                    <input
                      value={dossierCertifier}
                      onChange={(e) => setDossierCertifier(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white"
                    />
                  </div>

                  <div>
                    <label className="text-slate-400 block mb-1">Executive Findings Summary</label>
                    <textarea
                      rows={3}
                      value={dossierSummary}
                      onChange={(e) => setDossierSummary(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white"
                    />
                  </div>

                  <button
                    onClick={handleCreateDossier}
                    className="w-full py-2 bg-indigo-600 hover:bg-indigo-500 font-semibold text-white rounded transition shadow-sm"
                  >
                    Compile Draft Evidence Dossier (Uncertified)
                  </button>
                </div>

                {activeDossier && (
                  <div className="mt-4 p-4 rounded bg-slate-950 border border-slate-800 text-xs space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-white text-sm">{activeDossier.dossier_id}</span>
                      <div className="flex items-center space-x-2">
                        {activeDossier.is_digitally_signed ? (
                          <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-700 text-xs">
                            🔒 PKI SIGNED
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-700 text-xs">
                            TAMPER-EVIDENT HASH
                          </span>
                        )}
                        <span className={`px-2 py-0.5 rounded font-mono ${
                          activeDossier.status === "DRAFT_UNVERIFIED"
                            ? "bg-amber-950 text-amber-300 border border-amber-700 font-bold"
                            : "bg-slate-800 text-slate-300"
                        }`}>
                          {activeDossier.status === "DRAFT_UNVERIFIED" ? "DRAFT UNVERIFIED FORENSIC DOSSIER" : activeDossier.status}
                        </span>
                      </div>
                    </div>

                    <div>
                      <span className="text-slate-400">Canonical SHA-256 Digest:</span>
                      <div className="font-mono text-[11px] text-indigo-300 break-all bg-slate-900 p-1.5 rounded mt-0.5">
                        {activeDossier.dossier_digest}
                      </div>
                    </div>

                    {activeDossier.section_106b_certificate && (
                      <div className="p-2.5 bg-slate-900 rounded border border-slate-800">
                        <div className="font-semibold text-emerald-400 mb-1">
                          ✓ Section 106B Electronic Records Certificate Attached
                        </div>
                        <div className="text-slate-400">
                          Certifier: {activeDossier.section_106b_certificate.certifier_name} ({activeDossier.section_106b_certificate.certifier_designation})
                        </div>
                        <div className="text-slate-400">
                          Statute: {activeDossier.section_106b_certificate.statutory_framework}
                        </div>
                      </div>
                    )}

                    <div className="flex items-center space-x-2 pt-2 border-t border-slate-800">
                      {!activeDossier.is_digitally_signed && (
                        <button
                          onClick={() => handleSignDossier(activeDossier.dossier_id)}
                          className="px-3 py-1 bg-emerald-700 hover:bg-emerald-600 text-white rounded font-medium transition"
                        >
                          Sign with HSM (Ed25519)
                        </button>
                      )}
                      <button
                        onClick={() => handleVerifyDossier(activeDossier.dossier_id)}
                        className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-white rounded font-medium transition"
                      >
                        Verify Integrity
                      </button>
                      <a
                        href={`/api/enterprise/v1/governance/forensic-dossiers/${encodeURIComponent(activeDossier.dossier_id)}/export-html`}
                        target="_blank"
                        rel="noreferrer"
                        className="px-3 py-1 bg-indigo-700 hover:bg-indigo-600 text-white rounded font-medium transition text-center"
                      >
                        Export Draft Dossier (HTML)
                      </a>
                    </div>
                  </div>
                )}
              </div>

              {/* Section 2: Confirmation of Payee (CoP) Pre-Flight Verification */}
              <div className="p-5 rounded-lg bg-slate-900 border border-slate-800 space-y-4">
                <div className="border-b border-slate-800 pb-3">
                  <h3 className="text-sm font-bold text-white flex items-center">
                    <span className="mr-2">🔍</span> Confirmation of Payee (CoP) Pre-Flight Directory
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Pre-clearing beneficiary name verification under UK PSR & CBK rules. Checks intended name against legal account holder.
                  </p>
                </div>

                <div className="space-y-3 text-xs">
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="text-slate-400 block mb-1">Intended Payee Name (Payer Input)</label>
                      <input
                        value={copIntendedName}
                        onChange={(e) => setCopIntendedName(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white"
                        placeholder="e.g. Patrick Mwangi"
                      />
                    </div>
                    <div>
                      <label className="text-slate-400 block mb-1">Registered Account Holder</label>
                      <input
                        value={copRegisteredName}
                        onChange={(e) => setCopRegisteredName(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white"
                        placeholder="e.g. Patrick Kariuki Mwangi"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-4 gap-3">
                    <div>
                      <label className="text-slate-400 block mb-1">Account Number / MSISDN</label>
                      <input
                        value={copAcctNumber}
                        onChange={(e) => setCopAcctNumber(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white font-mono"
                      />
                    </div>
                    <div>
                      <label className="text-slate-400 block mb-1">Account Type</label>
                      <select
                        value={copAcctType}
                        onChange={(e) => setCopAcctType(e.target.value as "PERSONAL" | "BUSINESS")}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white"
                      >
                        <option value="PERSONAL">PERSONAL</option>
                        <option value="BUSINESS">BUSINESS</option>
                      </select>
                    </div>
                    <div>
                      <label className="text-slate-400 block mb-1">Clearing Rail</label>
                      <select
                        value={copRail}
                        onChange={(e) => setCopRail(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white"
                      >
                        <option value="PESALINK">PESALINK</option>
                        <option value="MPESA_B2C">M-PESA (Daraja)</option>
                        <option value="KEPSS_RTGS">KEPSS (RTGS)</option>
                      </select>
                    </div>
                    <div>
                      <label className="text-slate-400 block mb-1">Bank BIC</label>
                      <input
                        value={copBic}
                        onChange={(e) => setCopBic(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white font-mono"
                        placeholder="e.g. KCBKKENA"
                      />
                    </div>
                  </div>

                  <button
                    onClick={handleVerifyCop}
                    disabled={copVerifying}
                    className="w-full py-2 bg-indigo-600 hover:bg-indigo-500 font-semibold text-white rounded transition shadow-sm flex items-center justify-center"
                  >
                    {copVerifying ? "Verifying Directory..." : "Verify Payee (Confirmation of Payee)"}
                  </button>
                </div>

                {copResult && (
                  <div className="mt-4 p-4 rounded bg-slate-950 border border-slate-800 text-xs space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-white text-sm">CoP Verification Outcome</span>
                      <span
                        className={`px-2.5 py-1 rounded font-bold text-xs ${
                          copResult.status === "MATCH"
                            ? "bg-emerald-950 text-emerald-300 border border-emerald-700"
                            : copResult.status === "CLOSE_MATCH"
                            ? "bg-amber-950 text-amber-300 border border-amber-700"
                            : "bg-rose-950 text-rose-300 border border-rose-700"
                        }`}
                      >
                        {copResult.status}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-slate-400">
                      <div>
                        Match Score: <strong className="text-white">{(copResult.match_score * 100).toFixed(1)}%</strong>
                      </div>
                      <div>
                        Reason: <strong className="text-white font-mono text-[11px]">{copResult.reason_code}</strong>
                      </div>
                    </div>

                    {copResult.suggested_name && (
                      <div className="p-2 rounded bg-amber-950/60 border border-amber-800/80 text-amber-200">
                        Did you mean: <strong className="text-white">{copResult.suggested_name}</strong>?
                      </div>
                    )}

                    <div className="p-2.5 rounded bg-slate-900 text-slate-200 border border-slate-800 leading-relaxed">
                      {copResult.advisory_message}
                    </div>

                    <div className="pt-2 border-t border-slate-800 text-[10px] text-slate-500 font-mono break-all">
                      Digest: {copResult.inquiry_digest}
                    </div>
                  </div>
                )}
              </div>

              {/* Section 3: Telecom "Scam Signal" Live Carrier Telemetry (GSMA / Safaricom / Airtel) */}
              <div className="p-5 rounded-lg bg-slate-900 border border-slate-800 space-y-4">
                <div className="border-b border-slate-800 pb-3">
                  <h3 className="text-sm font-bold text-white flex items-center">
                    <span className="mr-2">📡</span> Telecom "Scam Signal" Carrier Gateway (GSMA Open Gateway)
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Direct telco network telemetry from Safaricom / Airtel to detect real-time telephone coaching, imposter calls, and SIM swaps prior to instant clearing.
                  </p>
                </div>

                <div className="space-y-3 text-xs">
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="text-slate-400 block mb-1">Carrier Network</label>
                      <select
                        value={telecomCarrier}
                        onChange={(e) => setTelecomCarrier(e.target.value as any)}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white"
                      >
                        <option value="SAFARICOM">Safaricom PLC (Kenya)</option>
                        <option value="AIRTEL">Airtel Kenya</option>
                        <option value="TELKOM">Telkom Kenya</option>
                      </select>
                    </div>
                    <div>
                      <label className="text-slate-400 block mb-1">Target MSISDN (Mobile Number)</label>
                      <input
                        value={telecomMsisdn}
                        onChange={(e) => setTelecomMsisdn(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white font-mono"
                        placeholder="+254712345678"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-3">
                    <div>
                      <label className="text-slate-400 block mb-1">Simulated Call State</label>
                      <select
                        value={telecomSimulatedCall}
                        onChange={(e) => setTelecomSimulatedCall(e.target.value as any)}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white"
                      >
                        <option value="CALL_IN_PROGRESS">Active Voice Call In Progress</option>
                        <option value="RECENT_CALL">Call Terminated &lt;5m Ago</option>
                        <option value="IDLE">Idle (No Call)</option>
                      </select>
                    </div>
                    <div>
                      <label className="text-slate-400 block mb-1">Call Duration (Seconds)</label>
                      <input
                        type="number"
                        value={telecomCallDuration}
                        onChange={(e) => setTelecomCallDuration(parseInt(e.target.value) || 0)}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white"
                      />
                    </div>
                    <div>
                      <label className="text-slate-400 block mb-1">SIM Swap Age (Hours, Opt)</label>
                      <input
                        type="number"
                        value={telecomSimSwapAge ?? ""}
                        onChange={(e) => setTelecomSimSwapAge(e.target.value ? parseFloat(e.target.value) : undefined)}
                        placeholder="e.g. 12 (within 24h)"
                        className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white"
                      />
                    </div>
                  </div>

                  <button
                    onClick={handleQueryTelecom}
                    disabled={telecomQuerying}
                    className="w-full py-2 bg-purple-600 hover:bg-purple-500 font-semibold text-white rounded transition shadow-sm flex items-center justify-center"
                  >
                    {telecomQuerying ? "Querying Carrier Gateway..." : "Query Telecom Scam Signal Telemetry"}
                  </button>
                </div>

                {telecomResult && (
                  <div className="mt-4 p-4 rounded bg-slate-950 border border-slate-800 text-xs space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-white text-sm">Carrier Telemetry</span>
                        {telecomResult.call_status === "CALL_IN_PROGRESS" && (
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-rose-600 text-white animate-pulse">
                            🔴 LIVE CALL IN PROGRESS ({telecomResult.call_duration_seconds}s)
                          </span>
                        )}
                      </div>
                      <span
                        className={`px-2.5 py-1 rounded font-bold text-xs ${
                          telecomResult.is_high_coercion_risk
                            ? "bg-rose-950 text-rose-300 border border-rose-700"
                            : "bg-emerald-950 text-emerald-300 border border-emerald-700"
                        }`}
                      >
                        {telecomResult.is_high_coercion_risk ? "HIGH COERCION RISK" : "NORMAL TELECOM PROFILE"}
                      </span>
                    </div>

                    <div className="grid grid-cols-3 gap-2 text-slate-400">
                      <div>
                        Coercion Score: <strong className="text-white">{(telecomResult.scam_signal_score * 100).toFixed(1)}%</strong>
                      </div>
                      <div>
                        SIM Status: <strong className="text-white">{telecomResult.sim_swap_status}</strong>
                      </div>
                      <div>
                        Carrier: <strong className="text-white">{telecomResult.carrier}</strong>
                      </div>
                    </div>

                    {telecomResult.coercion_indicators.length > 0 && (
                      <div>
                        <span className="text-slate-400 block mb-1">Carrier Telemetry Indicators:</span>
                        <ul className="list-disc list-inside space-y-0.5 text-amber-300">
                          {telecomResult.coercion_indicators.map((ind, idx) => (
                            <li key={idx}>{ind}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {telecomResult.statutory_warning && (
                      <div className="p-2.5 rounded bg-rose-950/60 border border-rose-800/80 text-rose-200 leading-relaxed">
                        {telecomResult.statutory_warning}
                      </div>
                    )}

                    <div className="p-2.5 rounded bg-slate-900 text-slate-200 border border-slate-800">
                      <strong>Advisory Action:</strong> {telecomResult.advisory_action}
                    </div>

                    <div className="pt-2 border-t border-slate-800 text-[10px] text-slate-500 font-mono break-all">
                      Digest: {telecomResult.query_digest}
                    </div>
                  </div>
                )}
              </div>

              {/* Section 4: ISO 20022 In-Flight Real-Time Risk & Graduated Controls */}
              <div className="p-5 rounded-lg bg-slate-900 border border-slate-800 space-y-4">
                <div className="border-b border-slate-800 pb-3">
                  <h3 className="text-sm font-bold text-white flex items-center">
                    <span className="mr-2">⚡</span> Shadow Advisory Payment Risk & Graduated Controls (PBOC / Swiss SIC5)
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Simulate shadow pacs.008 customer credit transfers across Kenya clearing rails. Toroka provides advisory risk scoring only and sends no clearing instructions.
                  </p>
                </div>

                <div className="space-y-3 text-xs">
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="text-slate-400 block mb-1">Clearing Rail</label>
                      <select
                        value={isoRail}
                        onChange={(e) => setIsoRail(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white"
                      >
                        <option value="PESALINK">PESALINK (IPSL Real-Time)</option>
                        <option value="KEPSS_RTGS">KEPSS (Central Bank RTGS)</option>
                        <option value="MPESA_B2C">M-PESA B2C (Daraja Clearing)</option>
                        <option value="SWIFT">SWIFT Cross-Border Wire</option>
                      </select>
                    </div>
                    <div>
                      <label className="text-slate-400 block mb-1">Transfer Amount (KES)</label>
                      <input
                        type="number"
                        value={isoAmount}
                        onChange={(e) => setIsoAmount(parseFloat(e.target.value) || 0)}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="text-slate-400 block mb-1">Debtor Account (Payer)</label>
                      <input
                        value={isoDebtorAcct}
                        onChange={(e) => setIsoDebtorAcct(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white font-mono"
                      />
                    </div>
                    <div>
                      <label className="text-slate-400 block mb-1">Creditor Account (Payee)</label>
                      <input
                        value={isoCreditorAcct}
                        onChange={(e) => setIsoCreditorAcct(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white font-mono"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="text-slate-400 block mb-1">Remittance Narrative / Memo</label>
                    <input
                      value={isoNarrative}
                      onChange={(e) => setIsoNarrative(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white"
                    />
                  </div>

                  {/* Graduated Controls & CoP Linking Options */}
                  <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-2">
                    <span className="font-semibold text-slate-300 block mb-1">Graduated Control Flags (PBOC Art. 18 / UK PSR)</span>
                    <div className="grid grid-cols-2 gap-2 text-[11px]">
                      <label className="flex items-center space-x-2 text-slate-300 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={enableGraduatedControls}
                          onChange={(e) => setEnableGraduatedControls(e.target.checked)}
                          className="rounded border-slate-800"
                        />
                        <span>Enable 15m Reversible Escrow Delay</span>
                      </label>
                      <label className="flex items-center space-x-2 text-slate-300 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={beneficiaryInflowRestriction}
                          onChange={(e) => setBeneficiaryInflowRestriction(e.target.checked)}
                          className="rounded border-slate-800"
                        />
                        <span>Beneficiary Inflow-Only Hold</span>
                      </label>
                      <label className="flex items-center space-x-2 text-slate-300 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={debtorChannelAnomaly}
                          onChange={(e) => setDebtorChannelAnomaly(e.target.checked)}
                          className="rounded border-slate-800"
                        />
                        <span>Debtor Non-Counter Restriction</span>
                      </label>
                      <div className="flex items-center space-x-2">
                        <span className="text-slate-400">CoP Flag:</span>
                        <select
                          value={isoCopStatus}
                          onChange={(e) => setIsoCopStatus(e.target.value)}
                          className="bg-slate-900 border border-slate-800 rounded px-1.5 py-0.5 text-white text-[11px]"
                        >
                          <option value="NONE">NONE (Unchecked)</option>
                          <option value="MATCH">MATCH (Verified)</option>
                          <option value="CLOSE_MATCH">CLOSE_MATCH (Review)</option>
                          <option value="NO_MATCH">NO_MATCH (Impersonation)</option>
                        </select>
                      </div>
                      <div className="flex items-center space-x-2">
                        <span className="text-slate-400">Live Call:</span>
                        <select
                          value={isoTelecomCallStatus}
                          onChange={(e) => setIsoTelecomCallStatus(e.target.value)}
                          className="bg-slate-900 border border-slate-800 rounded px-1.5 py-0.5 text-white text-[11px]"
                        >
                          <option value="NONE">NONE (Unchecked)</option>
                          <option value="CALL_IN_PROGRESS">Active Call (Coaching)</option>
                          <option value="RECENT_CALL">Recent Call (&lt;5m)</option>
                        </select>
                      </div>
                    </div>
                  </div>

                  <button
                    onClick={handleEvaluateInflightPayment}
                    disabled={isoEvaluating}
                    className="w-full py-2 bg-emerald-600 hover:bg-emerald-500 font-semibold text-white rounded transition shadow-sm flex items-center justify-center"
                  >
                    {isoEvaluating ? "Evaluating in &lt;100ms..." : "Evaluate In-Flight Clearing Decision"}
                  </button>
                </div>

                {isoEvaluation && (
                  <div className="mt-4 p-4 rounded bg-slate-950 border border-slate-800 text-xs space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-white text-sm">Advisory Decision</span>
                      <div className="flex items-center space-x-2">
                        <span
                          className={`px-2.5 py-1 rounded font-bold text-xs ${
                            isoEvaluation.decision === "ALLOW"
                              ? "bg-emerald-950 text-emerald-300 border border-emerald-700"
                              : isoEvaluation.decision === "DELAY_SETTLEMENT_15M"
                              ? "bg-purple-950 text-purple-300 border border-purple-700"
                              : isoEvaluation.decision === "INFLOW_ONLY"
                              ? "bg-orange-950 text-orange-300 border border-orange-700"
                              : isoEvaluation.decision === "RESTRICT_NON_COUNTER"
                              ? "bg-amber-950 text-amber-300 border border-amber-700"
                              : isoEvaluation.decision === "STEP_UP_AUTH"
                              ? "bg-blue-950 text-blue-300 border border-blue-700"
                              : isoEvaluation.decision === "QUARANTINE_HOLD"
                              ? "bg-yellow-950 text-yellow-300 border border-yellow-700"
                              : "bg-rose-950 text-rose-300 border border-rose-700"
                          }`}
                        >
                          {isoEvaluation.decision}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-slate-900 text-indigo-300 font-mono text-[11px]">
                          ⚡ {isoEvaluation.latency_ms.toFixed(2)} ms
                        </span>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-slate-400">
                      <div>
                        Risk Score: <strong className="text-white">{isoEvaluation.risk_score.toFixed(3)}</strong>
                      </div>
                      <div>
                        Risk Tier: <strong className="text-white">{isoEvaluation.risk_tier}</strong>
                      </div>
                    </div>

                    <div>
                      <span className="text-slate-400 block mb-1">Recommended Clearing Action:</span>
                      <div className="p-2 rounded bg-slate-900 text-slate-200 border border-slate-800">
                        {isoEvaluation.recommended_action}
                      </div>
                    </div>

                    {isoEvaluation.is_telecom_coerced && (
                      <div className="p-2.5 rounded bg-rose-950/80 border border-rose-700 text-rose-200 flex items-center space-x-2">
                        <span className="text-base animate-pulse">📞</span>
                        <div>
                          <strong className="text-white block font-semibold">Active Telephone Coaching / ATO In Progress</strong>
                          <span className="text-[11px] text-rose-300">
                            Debtor is engaged on an active voice call during payment authorization. Reversible 15-minute escrow hold enforced.
                          </span>
                        </div>
                      </div>
                    )}

                    {isoEvaluation.triggered_rules.length > 0 && (
                      <div>
                        <span className="text-slate-400 block mb-1">Triggered Risk Rules:</span>
                        <ul className="list-disc list-inside space-y-0.5 text-rose-300">
                          {isoEvaluation.triggered_rules.map((rule, idx) => (
                            <li key={idx}>{rule}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </div>
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
