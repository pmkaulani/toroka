from __future__ import annotations

from datetime import datetime, timezone
import pytest

from toroka_enterprise.governance import (
    ApprovalDecision,
    BoundEvidenceItem,
    ComponentRegistry,
    ComponentSuspended,
    ComponentType,
    DeploymentEnvironment,
    GateStatus,
    GovernanceIncident,
    GovernanceStatus,
    GovernedAIProvider,
    GovernedComponent,
    InMemoryKillSwitchStore,
    IncidentCategory,
    IncidentSeverity,
    IncidentStatus,
    KillSwitch,
    MANDATORY_GATES,
    PillarStatus,
    ProductionReleaseManifest,
    ReadinessAssessment,
    ReadinessGate,
    ReleaseStatus,
    RiskTier,
    SuspensionRecord,
    TorokaControlPlane,
    TorokaEvidencePassport,
    ValidationMetric,
    ValidationResult,
    ValidationRun,
    approve_component,
    compute_evidence_digest,
    evaluate_production_readiness,
)
from toroka_enterprise.intelligence.copilot.contracts import (
    CopilotTaskType,
    EvidenceContext,
    EvidenceItem,
    GroundedClaim,
    InvestigationCopilotResponse,
)
from toroka_enterprise.intelligence.copilot.grounding import (
    filter_unsupported_claims,
    validate_summary_and_report_grounding,
)
from toroka_enterprise.intelligence.network.resolution import (
    AttributeRiskTier,
    EntityLinkCandidate,
    EntityLinkStatus,
    EntityResolutionEngine,
    MatchType,
    can_collapse_entities,
    classify_attribute_risk,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


# =============================================================================
# Issue 1: Production Promotion Gate Enforcement
# =============================================================================

def test_production_promotion_requires_all_13_mandatory_gates():
    now = _utc_now()
    comp = GovernedComponent(
        component_id="detector-account-takeover",
        version="1.2.0",
        component_type=ComponentType.DETECTOR,
        name="Account Takeover Detector",
        description="Detects rapid credential modification followed by high-value transfer",
        risk_tier=RiskTier.HIGH,
        status=GovernanceStatus.APPROVED,
        owner_team="fraud-analytics@bank.example",
        source_digest="sha256_src_1",
        configuration_digest="sha256_cfg_1",
        created_at=now,
        approved_at=now,
        approved_by="officer.alice",
    )

    # All 13 mandatory gates passed
    gates = tuple(
        ReadinessGate(
            gate_name=gate,
            status=GateStatus.PASS,
            verified_by="qa-pipeline",
            rationale=f"Automated gate verification passed for {gate}",
        )
        for gate in MANDATORY_GATES
    )
    all_gates_assessment = ReadinessAssessment(
        installation_id="bank-pilot-ke",
        release_version="1.2.0",
        overall_status=GateStatus.PASS,
        gates=gates,
        evaluated_at=now.isoformat(),
    )

    val_run = ValidationRun(
        run_id="val-prod-001",
        component_id="detector-account-takeover",
        component_version="1.2.0",
        dataset_digest="sha256:abc123golden",
        configuration_digest="sha256_cfg_1",
        metrics=(),
        result=ValidationResult.PASS,
        evaluator="validator.carol",
        started_at=now.isoformat(),
        completed_at=now.isoformat(),
    )

    approvals = (
        ApprovalDecision(
            component_id="detector-account-takeover",
            component_version="1.2.0",
            approved_by="officer.alice",
            approved_at=now,
            validation_run_id="val-prod-001",
            validation_digest="sha256:abc123golden",
            rationale="Approved by Model Risk Management",
        ),
        ApprovalDecision(
            component_id="detector-account-takeover",
            component_version="1.2.0",
            approved_by="authoriser.david",
            approved_at=now,
            validation_run_id="val-prod-001",
            validation_digest="sha256:abc123golden",
            rationale="Approved by Bank Operations Lead",
        ),
    )

    manifest = ProductionReleaseManifest(
        release_id="rel-2026-11-001",
        version="1.2.0",
        environment=DeploymentEnvironment.PILOT,
        status=ReleaseStatus.STAGED,
        components={"detector-account-takeover": "1.2.0"},
        readiness_assessment=all_gates_assessment,
        validation_runs=("val-prod-001",),
        approval_records=("app-alice-001", "app-david-002"),
        created_by="release.manager",
        created_at=now,
    )

    # 1. Manifest digest must be valid
    assert manifest.verify_manifest_integrity() is True

    # 2. Promotion eligibility should succeed with zero suspensions and zero blocking incidents
    eligible, reasons = manifest.validate_promotion_eligibility(
        has_active_suspensions=False,
        has_blocking_incidents=False,
    )
    assert eligible is True
    assert reasons == []

    # 3. Blocked if active kill switch suspension exists
    blocked_susp, susp_reasons = manifest.validate_promotion_eligibility(
        has_active_suspensions=True,
        has_blocking_incidents=False,
    )
    assert blocked_susp is False
    assert any("kill switch" in r.lower() for r in susp_reasons)

    # 4. Blocked if active blocking incident exists
    blocked_inc, inc_reasons = manifest.validate_promotion_eligibility(
        has_active_suspensions=False,
        has_blocking_incidents=True,
    )
    assert blocked_inc is False
    assert any("incident" in r.lower() for r in inc_reasons)

    # 5. Blocked if even one mandatory gate is missing
    twelve_gates = gates[:-1]
    partial_assessment = ReadinessAssessment(
        installation_id="bank-pilot-ke",
        release_version="1.2.0",
        overall_status=GateStatus.PASS,
        gates=twelve_gates,
        evaluated_at=now.isoformat(),
    )
    partial_manifest = ProductionReleaseManifest(
        release_id="rel-2026-11-002",
        version="1.2.0",
        environment=DeploymentEnvironment.PILOT,
        status=ReleaseStatus.STAGED,
        components={"detector-account-takeover": "1.2.0"},
        readiness_assessment=partial_assessment,
        validation_runs=("val-prod-001",),
        approval_records=("app-alice-001", "app-david-002"),
        created_by="release.manager",
        created_at=now,
    )
    partial_eligible, partial_reasons = partial_manifest.validate_promotion_eligibility()
    assert partial_eligible is False
    assert any("mandatory readiness gate" in r.lower() for r in partial_reasons)


# =============================================================================
# Issue 2: Cryptographically Bound Evidence Passport
# =============================================================================

def test_evidence_passport_cryptographic_binding_and_tamper_detection():
    now = _utc_now()
    items = [
        BoundEvidenceItem(
            evidence_id="ev-login-001",
            evidence_digest=compute_evidence_digest({"ip": "196.201.214.10", "action": "LOGIN", "status": "SUCCESS"}),
            source_record_id="audit_row_9872",
            source_system="core_banking_iam",
        ),
        BoundEvidenceItem(
            evidence_id="ev-beneficiary-002",
            evidence_digest=compute_evidence_digest({"account": "ACC_44921", "action": "ADD_BENEFICIARY", "dest": "ACC_99210"}),
            source_record_id="beneficiary_audit_102",
            source_system="payment_portal",
        ),
    ]

    passport = TorokaEvidencePassport.create(
        passport_id="pass-alpha-2026",
        installation_id="bank-pilot-ke",
        case_id="case-investigation-771",
        detection_run_id="run-det-441",
        component_versions={"detector-account-takeover": "1.2.0", "copilot-engine": "2.0.1"},
        evidence_records=items,
        issued_at=now,
        data_contract_fingerprint="contract-v1.2-sha256-abc",
        policy_version="v1.2",
    )

    # Initial passport must be cryptographically valid
    assert passport.verify_integrity() is True
    assert passport.evidence_count == 2
    assert passport.data_contract_fingerprint == "contract-v1.2-sha256-abc"

    # Tampering test 1: Modifying evidence item content
    tampered_items = [
        BoundEvidenceItem(
            evidence_id="ev-login-001",
            evidence_digest="sha256:tamperedcontentfake",  # TAMPERED
            source_record_id="audit_row_9872",
            source_system="core_banking_iam",
        ),
        items[1],
    ]
    tampered_passport_1 = TorokaEvidencePassport(
        passport_id=passport.passport_id,
        finding_id=passport.finding_id,
        case_id=passport.case_id,
        installation_id=passport.installation_id,
        finding_type=passport.finding_type,
        finding_status=passport.finding_status,
        component_versions=passport.component_versions,
        configuration_digest=passport.configuration_digest,
        evidence_count=2,
        source_systems=passport.source_systems,
        detection_time=passport.detection_time,
        evidence_records=tuple(t.to_dict() for t in tampered_items),
        passport_digest=passport.passport_digest,
        data_contract_fingerprint=passport.data_contract_fingerprint,
        policy_version=passport.policy_version,
    )
    assert tampered_passport_1.verify_integrity() is False

    # Tampering test 2: Modifying source record ID
    tampered_items_2 = [
        items[0],
        BoundEvidenceItem(
            evidence_id="ev-beneficiary-002",
            evidence_digest=items[1].evidence_digest,
            source_record_id="tampered_audit_row_9999",  # TAMPERED
            source_system="payment_portal",
        ),
    ]
    tampered_passport_2 = TorokaEvidencePassport(
        passport_id=passport.passport_id,
        finding_id=passport.finding_id,
        case_id=passport.case_id,
        installation_id=passport.installation_id,
        finding_type=passport.finding_type,
        finding_status=passport.finding_status,
        component_versions=passport.component_versions,
        configuration_digest=passport.configuration_digest,
        evidence_count=2,
        source_systems=passport.source_systems,
        detection_time=passport.detection_time,
        evidence_records=tuple(t.to_dict() for t in tampered_items_2),
        passport_digest=passport.passport_digest,
        data_contract_fingerprint=passport.data_contract_fingerprint,
        policy_version=passport.policy_version,
    )
    assert tampered_passport_2.verify_integrity() is False


# =============================================================================
# Issue 3: Copilot Summary & Report Grounding Validation
# =============================================================================

def test_copilot_grounding_neutralizes_speculative_assertions():
    item = EvidenceItem.create(
        evidence_id="ev:01",
        installation_id="bank-pilot-ke",
        case_id="case-100",
        source_system="core_iam",
        source_record_id="rec-1",
        excerpt="User logged in from Nairobi IP 196.201.214.10",
        event_time=_utc_now(),
    )
    evidence_ctx = EvidenceContext(
        installation_id="bank-pilot-ke",
        case_id="case-100",
        items=(item,),
    )

    # Speculative text with ungrounded takeover claim and missing evidence citation
    speculative_summary = "This case represents a severe account takeover where funds were rapidly stolen."
    speculative_report = """# Investigation Report
A malicious actor executed an account takeover and stole customer funds.
The employee colluded with a known mule account."""

    grounded_sum, grounded_rep, sum_grounded, rep_grounded, s_flags, r_flags = validate_summary_and_report_grounding(
        summary=speculative_summary,
        report_markdown=speculative_report,
        valid_claims=[],
        evidence_context=evidence_ctx,
    )

    # Speculative narrative must be flagged as ungrounded and neutralized
    assert sum_grounded is False
    assert rep_grounded is False
    assert len(s_flags) > 0
    assert any("account takeover" in f for f in s_flags)
    assert len(r_flags) > 0
    assert "they do not, on their own, establish" in grounded_sum
    assert "in draft text have been flagged" in grounded_rep


# =============================================================================
# Issue 4: Explicit AI Provider & Fallback Provenance
# =============================================================================

def test_copilot_response_explicit_provenance_and_fallback():
    now = _utc_now()
    resp = InvestigationCopilotResponse(
        response_id="resp-1",
        thread_id="th-1",
        case_id="case-990",
        installation_id="bank-pilot-ke",
        task_type=CopilotTaskType.EXPLAIN_TIMELINE,
        summary="Three events observed across core banking and IAM logs.",
        claims=(),
        requested_provider="azure_openai",
        actual_provider="deterministic_rule_based",
        requested_model="gpt-4o",
        actual_model="toroka-rules-v1",
        fallback_used=True,
        fallback_reason="Upstream AI provider timeout after 10000ms",
        is_degraded_mode=True,
        provider_version="1.2.0",
        summary_grounded=True,
        report_grounded=True,
    )

    assert resp.fallback_used is True
    assert resp.is_degraded_mode is True
    assert resp.requested_provider == "azure_openai"
    assert resp.actual_provider == "deterministic_rule_based"
    assert "timeout" in resp.fallback_reason.lower()


# =============================================================================
# Issue 5: Persistent Kill Switch Authority
# =============================================================================

def test_persistent_kill_switch_store_and_fault_isolation():
    store = InMemoryKillSwitchStore()
    ks = KillSwitch(store=store)
    now = _utc_now()

    assert ks.is_suspended("detector-fan-out", "1.0.0") is False

    # Suspend component
    rec = ks.suspend(
        component_id="detector-fan-out",
        version="1.0.0",
        actor="ciso.officer",
        reason="Elevated false positive rate detected in production branch",
        now=now,
    )

    assert rec.is_active is True
    assert ks.is_suspended("detector-fan-out", "1.0.0") is True

    # Check that another KillSwitch instance sharing the same store sees the suspension
    ks_secondary = KillSwitch(store=store)
    assert ks_secondary.is_suspended("detector-fan-out", "1.0.0") is True

    with pytest.raises(ComponentSuspended) as exc_info:
        ks_secondary.assert_active("detector-fan-out", "1.0.0")
    assert "suspended by ciso.officer" in str(exc_info.value)

    # Resume component
    resumed = ks_secondary.resume(
        component_id="detector-fan-out",
        version="1.0.0",
        actor="ciso.officer",
        reason="Model recalibrated and retrained; verified on golden test suite",
        now=now,
    )
    assert resumed.is_active is False
    assert ks.is_suspended("detector-fan-out", "1.0.0") is False
    assert ks_secondary.is_suspended("detector-fan-out", "1.0.0") is False


# =============================================================================
# Issue 6: Entity Resolution Identifier Governance Tightening
# =============================================================================

def test_entity_resolution_governance_and_attribute_risk_classification():
    # 1. Attribute risk classification
    assert classify_attribute_risk("national_id_hash") == AttributeRiskTier.STRONG_IDENTIFIER
    assert classify_attribute_risk("passport_hash") == AttributeRiskTier.STRONG_IDENTIFIER
    assert classify_attribute_risk("phone") == AttributeRiskTier.COMMODITY_IDENTIFIER
    assert classify_attribute_risk("device_id") == AttributeRiskTier.COMMODITY_IDENTIFIER
    assert classify_attribute_risk("ip_address") == AttributeRiskTier.EPHEMERAL_INFRASTRUCTURE
    assert classify_attribute_risk("branch_workstation") == AttributeRiskTier.EPHEMERAL_INFRASTRUCTURE

    # 2. Automated proposal must never set SAME_ENTITY_CONFIRMED
    cand = EntityResolutionEngine.propose_candidate(
        installation_id="bank-pilot-ke",
        source_key="account:ACC_001",
        target_key="account:ACC_002",
        attribute_type="phone",
        attribute_value="0712345678",
        source_systems=["core_banking"],
    )
    assert cand.status == EntityLinkStatus.POSSIBLY_RELATED
    assert cand.is_confirmed_identity is False
    assert can_collapse_entities(cand) is False

    # 3. Direct instantiation of SAME_ENTITY_CONFIRMED without maker-checker review raises ValueError
    with pytest.raises(ValueError) as exc_info:
        EntityLinkCandidate(
            candidate_id="cand-unauthorized",
            installation_id="bank-pilot-ke",
            source_entity_key="account:ACC_001",
            target_entity_key="account:ACC_002",
            attribute_type="phone",
            attribute_value="0712345678",
            match_type=MatchType.EXACT,
            status=EntityLinkStatus.SAME_ENTITY_CONFIRMED,  # FORBIDDEN WITHOUT REVIEW
            confidence=1.0,
            reviewed_by=None,
            review_rationale=None,
        )
    assert "requires human maker-checker review" in str(exc_info.value)

    # 4. Human review on commodity token satisfies is_confirmed_identity
    reviewed = EntityResolutionEngine.apply_human_review(
        cand,
        reviewer_subject="investigator.alice",
        decision=EntityLinkStatus.SAME_ENTITY_CONFIRMED,
        rationale="Customer verified phone ownership during branch KYC refresh.",
    )
    assert reviewed.is_confirmed_identity is True
    assert can_collapse_entities(reviewed) is True

    # 5. Human review on ephemeral infrastructure alone CANNOT collapse identity without multi-source corroborate
    ip_cand = EntityResolutionEngine.propose_candidate(
        installation_id="bank-pilot-ke",
        source_key="account:ACC_001",
        target_key="account:ACC_003",
        attribute_type="ip_address",
        attribute_value="196.201.214.10",
        source_systems=["web_portal"],
        supporting_evidence=[{"event": "login"}],
    )
    reviewed_ip = EntityResolutionEngine.apply_human_review(
        ip_cand,
        reviewer_subject="investigator.alice",
        decision=EntityLinkStatus.SAME_ENTITY_CONFIRMED,
        rationale="Shared IP noted during investigation.",
    )
    assert reviewed_ip.is_confirmed_identity is True
    # Still blocked from collapsing identities because IP is ephemeral and only has 1 source system
    assert can_collapse_entities(reviewed_ip) is False


# =============================================================================
# Issue 7 & 8: Unified Toroka Control Plane & Health Assessment
# =============================================================================

def test_unified_control_plane_and_health_assessment():
    now = _utc_now()
    control_plane = TorokaControlPlane(
        installation_id="bank-pilot-ke",
        policy_version="v1.2",
    )

    # Register component
    comp = GovernedComponent(
        component_id="detector-layering",
        version="1.0.0",
        component_type=ComponentType.DETECTOR,
        name="Layering Detector",
        description="Identifies multi-hop fund dispersion",
        risk_tier=RiskTier.MODERATE,
        status=GovernanceStatus.ACTIVE,
        owner_team="aml-team@bank.example",
        source_digest="sha256_src_2",
        configuration_digest="sha256_cfg_2",
        created_at=now,
        approved_at=now,
        approved_by="officer.alice",
    )
    control_plane.register_component(comp)

    # Record validation
    val_run = ValidationRun(
        run_id="val-run-layering-1",
        component_id="detector-layering",
        component_version="1.0.0",
        dataset_digest="sha256:layering123",
        configuration_digest="sha256_cfg_2",
        metrics=(),
        result=ValidationResult.PASS,
        evaluator="validator.elena",
        started_at=now.isoformat(),
        completed_at=now.isoformat(),
    )
    control_plane.record_validation_run("detector-layering", "1.0.0", val_run)

    # Initial health check
    health = control_plane.get_system_governance_health()
    assert health.installation_id == "bank-pilot-ke"
    assert health.overall_status in (PillarStatus.HEALTHY, PillarStatus.WARNING)
    assert len(health.pillars) == 9
    assert "iam_policy" in health.pillars
    assert "registry" in health.pillars
    assert "evidence_lineage" in health.pillars
    assert "model_governance" in health.pillars
    assert "ai_governance" in health.pillars
    assert "release_gates" in health.pillars
    assert "fault_isolation" in health.pillars
    assert "incident_management" in health.pillars
    assert "auditability" in health.pillars

    # Record critical incident -> Health drops to CRITICAL and blocks readiness
    incident = GovernanceIncident(
        incident_id="inc-sec-001",
        installation_id="bank-pilot-ke",
        title="Unauthorized credential usage detected on payment connector",
        category=IncidentCategory.SECURITY_EVENT,
        severity=IncidentSeverity.CRITICAL,
        status=IncidentStatus.INVESTIGATING,
        affected_components=("detector-layering:1.0.0",),
        detected_at=now,
    )
    control_plane.record_incident(incident)

    critical_health = control_plane.get_system_governance_health()
    assert critical_health.overall_status == PillarStatus.CRITICAL
    assert critical_health.is_production_ready is False
    assert critical_health.blocking_incidents_count == 1
    assert critical_health.pillars["incident_management"].status == PillarStatus.CRITICAL
