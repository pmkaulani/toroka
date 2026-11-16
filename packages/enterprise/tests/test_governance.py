from __future__ import annotations

from datetime import datetime, timezone
import pytest

from toroka_enterprise.governance import (
    ApprovalDecision,
    ApprovalError,
    ComponentRegistry,
    ComponentSuspended,
    ComponentType,
    DeploymentEnvironment,
    DriftType,
    GateStatus,
    GovernanceIncident,
    GovernanceStatus,
    GovernedAIProvider,
    GovernedComponent,
    IncidentCategory,
    IncidentSeverity,
    IncidentStatus,
    KillSwitch,
    MANDATORY_GATES,
    ProductionReleaseManifest,
    ReadinessGate,
    RegistryError,
    ReleaseStatus,
    RiskTier,
    TorokaEvidencePassport,
    ValidationMetric,
    ValidationResult,
    ValidationRun,
    approve_component,
    calculate_validation_result,
    correlate_incident_to_cases,
    evaluate_copilot_benchmark,
    evaluate_metric,
    evaluate_metric_drift,
    evaluate_production_readiness,
    validate_detector_metrics,
    verify_provider_compliance,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def test_governed_component_invariants():
    t0 = _now()
    # 1. Valid DRAFT component
    comp = GovernedComponent(
        component_id="detector.fan_out",
        version="1.0.0",
        component_type=ComponentType.DETECTOR,
        name="Fan-Out Transfer Detector",
        status=GovernanceStatus.DRAFT,
        risk_tier=RiskTier.HIGH,
        owner_team="fraud_intelligence",
        source_digest="sha256_src_123",
        configuration_digest="sha256_cfg_456",
        created_at=t0,
        created_by="engineer_dan",
    )
    assert comp.component_id == "detector.fan_out"
    assert comp.status == GovernanceStatus.DRAFT

    # 2. Cannot create approved component without approval metadata
    with pytest.raises(ValueError, match="Approved components require approval metadata"):
        GovernedComponent(
            component_id="detector.fan_out",
            version="1.0.0",
            component_type=ComponentType.DETECTOR,
            name="Fan-Out Transfer Detector",
            status=GovernanceStatus.APPROVED,
            risk_tier=RiskTier.HIGH,
            owner_team="fraud_intelligence",
            source_digest="sha256_src",
            configuration_digest="sha256_cfg",
            created_at=t0,
            created_by="engineer_dan",
            approved_at=None,
            approved_by=None,
        )

    # 3. Cannot create active component without approval metadata
    with pytest.raises(ValueError, match="Active components must have approval metadata"):
        GovernedComponent(
            component_id="detector.fan_out",
            version="1.0.0",
            component_type=ComponentType.DETECTOR,
            name="Fan-Out Transfer Detector",
            status=GovernanceStatus.ACTIVE,
            risk_tier=RiskTier.HIGH,
            owner_team="fraud_intelligence",
            source_digest="sha256_src",
            configuration_digest="sha256_cfg",
            created_at=t0,
            created_by="engineer_dan",
        )


def test_approval_workflow_and_maker_checker():
    t0 = _now()
    comp_val = GovernedComponent(
        component_id="model.mule_risk",
        version="2.1.0",
        component_type=ComponentType.STATISTICAL_MODEL,
        name="Mule Account Risk Scorer",
        status=GovernanceStatus.VALIDATION,
        risk_tier=RiskTier.HIGH,
        owner_team="model_risk_management",
        source_digest="sha_src",
        configuration_digest="sha_cfg",
        created_at=t0,
        created_by="author_alice",
    )

    # Rejection: Maker-checker violation (author approves own high-risk model)
    with pytest.raises(ApprovalError, match="Maker-checker violation"):
        approve_component(
            comp_val,
            reviewer_subject="author_alice",
            validation_run_id="run_999",
            validation_digest="sha_val_run",
            rationale="Looks good to me",
            now=_now(),
        )

    # Success: Independent reviewer approves
    approved = approve_component(
        comp_val,
        reviewer_subject="reviewer_bob",
        validation_run_id="run_999",
        validation_digest="sha_val_run",
        rationale="Validation run passes all precision, recall, and stability criteria.",
        now=_now(),
    )
    assert approved.status == GovernanceStatus.APPROVED
    assert approved.approved_by == "reviewer_bob"
    assert approved.approved_at is not None


def test_detector_validation_framework():
    # 90 TP, 5 FP, 950 TN, 10 FN
    metrics = validate_detector_metrics(
        tp=90,
        fp=5,
        tn=950,
        fn=10,
        min_precision=0.85,
        min_recall=0.80,
        max_fpr=0.02,
        observed_latency_ms=18.5,
    )
    assert len(metrics) == 4
    prec = next(m for m in metrics if m.name == "precision")
    assert prec.result == ValidationResult.PASS
    assert prec.value > 0.90

    overall = calculate_validation_result(metrics)
    assert overall == ValidationResult.PASS

    # Now with high false positive rate
    metrics_failing = validate_detector_metrics(
        tp=50,
        fp=50,
        tn=900,
        fn=50,
        min_precision=0.85,
        min_recall=0.80,
    )
    assert calculate_validation_result(metrics_failing) == ValidationResult.FAIL


def test_component_registry_and_activation():
    reg = ComponentRegistry()
    t0 = _now()
    c1 = GovernedComponent(
        component_id="detector.pass_through",
        version="1.0.0",
        component_type=ComponentType.DETECTOR,
        name="Rapid Pass-Through Detector",
        status=GovernanceStatus.VALIDATION,
        risk_tier=RiskTier.MODERATE,
        owner_team="fraud",
        source_digest="s1",
        configuration_digest="c1",
        created_at=t0,
        created_by="eng_dan",
    )
    reg.register(c1)

    # Attempting to activate an unapproved component raises RegistryError
    with pytest.raises(RegistryError, match="Cannot activate an unapproved component"):
        reg.transition_status("detector.pass_through", "1.0.0", GovernanceStatus.ACTIVE, actor="ops", now=t0)

    # Approve and transition
    c_appr = approve_component(
        c1,
        reviewer_subject="chief_risk_officer",
        validation_run_id="val_01",
        validation_digest="dig_01",
        rationale="Passes validation",
        now=t0,
    )
    # Re-register or transition
    reg._components[(c1.component_id, c1.version)] = c_appr
    activated = reg.transition_status(c1.component_id, c1.version, GovernanceStatus.ACTIVE, actor="ops", now=t0)
    assert activated.status == GovernanceStatus.ACTIVE

    manifest = reg.get_active_manifest()
    assert manifest.get("detector.pass_through") == "1.0.0"


def test_kill_switch_granular_suspension():
    ks = KillSwitch()
    t0 = _now()

    assert not ks.is_suspended("detector.fan_out", "1.0.0")
    ks.assert_active("detector.fan_out", "1.0.0")

    # Suspend
    rec = ks.suspend(
        component_id="detector.fan_out",
        version="1.0.0",
        actor="oncall_secops",
        reason="Sudden alert spike indicating upstream feed corruption",
        incident_id="inc_2026_001",
        now=t0,
    )
    assert rec.is_active is True
    assert ks.is_suspended("detector.fan_out", "1.0.0")

    with pytest.raises(ComponentSuspended, match="is suspended by oncall_secops"):
        ks.assert_active("detector.fan_out", "1.0.0")

    # Resume
    resumed = ks.resume(
        component_id="detector.fan_out",
        version="1.0.0",
        actor="lead_authoriser",
        reason="Upstream feed repaired and revalidated",
        now=_now(),
    )
    assert not resumed.is_active
    assert not ks.is_suspended("detector.fan_out", "1.0.0")
    ks.assert_active("detector.fan_out", "1.0.0")


def test_incident_case_correlation():
    case_manifests = {
        "case_001": {"detector.fan_out", "model.baseline"},
        "case_002": {"detector.circular"},
        "case_003": {"detector.fan_out", "copilot.engine"},
    }
    impacted = correlate_incident_to_cases({"detector.fan_out"}, case_manifests)
    assert impacted == ["case_001", "case_003"]


def test_drift_evaluation():
    t0 = _now()
    # Normal fluctuation (5% change, threshold 20%)
    drift_none = evaluate_metric_drift(
        drift_id="d1",
        component_id="detector.mule",
        drift_type=DriftType.DETECTOR_VOLUME,
        metric_name="daily_alerts",
        baseline=100.0,
        observed=105.0,
        threshold=0.20,
        now=t0,
    )
    assert drift_none is None

    # Significant drift (50% change, threshold 20%)
    drift_alert = evaluate_metric_drift(
        drift_id="d2",
        component_id="detector.mule",
        drift_type=DriftType.DETECTOR_VOLUME,
        metric_name="daily_alerts",
        baseline=100.0,
        observed=160.0,
        threshold=0.20,
        now=t0,
    )
    assert drift_alert is not None
    assert drift_alert.severity in (IncidentSeverity.HIGH, IncidentSeverity.CRITICAL)


def test_evidence_passport_provenance():
    t0 = _now()
    passport = TorokaEvidencePassport(
        passport_id="pass_2026_004821",
        finding_id="FND-2026-004821",
        case_id="case_100",
        installation_id="BANK-KE-001",
        finding_type="EMPLOYEE_ACCESS_BEFORE_SENSITIVE_CHANGE",
        finding_status="UNDER_INVESTIGATION",
        component_versions={
            "detector": "EMP-ACCESS-1.4.2",
            "network": "NET-1.0.3",
            "reconstruction": "RECON-1.2.0",
        },
        configuration_digest="sha256_config_abc",
        evidence_count=17,
        source_systems=("iam_active_directory", "core_banking", "payments"),
        detection_time=t0,
        earliest_event_time=t0,
        evidence_at_detection_count=14,
        delayed_evidence_count=3,
        contradictions_count=2,
        evidence_debt_level="MEDIUM",
        alternative_explanations=("Customer telephone emergency instruction",),
    )
    assert passport.passport_digest != ""
    assert passport.verify_integrity() is True


def test_production_readiness_gates():
    gates = [
        ReadinessGate(gate_name=name, status=GateStatus.PASS, verified_by="auditor", rationale="Verified")
        for name in MANDATORY_GATES
    ]
    assessment_pass = evaluate_production_readiness(
        installation_id="BANK-KE-001",
        release_version="12.0.0",
        gates_input=gates,
        evaluated_at="2026-11-16T20:00:00Z",
    )
    assert assessment_pass.is_production_ready is True

    # One gate fails
    failing_gates = [
        ReadinessGate(
            gate_name=name,
            status=GateStatus.FAIL if name == "DR_TEST" else GateStatus.PASS,
            verified_by="auditor",
            rationale="DR test pending" if name == "DR_TEST" else "Verified",
        )
        for name in MANDATORY_GATES
    ]
    assessment_fail = evaluate_production_readiness(
        installation_id="BANK-KE-001",
        release_version="12.0.0",
        gates_input=failing_gates,
        evaluated_at="2026-11-16T20:00:00Z",
    )
    assert assessment_fail.is_production_ready is False


def test_ai_copilot_benchmark_and_third_party():
    test_runs = [
        {"grounded": True, "citations_correct": True, "unsupported_claims_present": False, "injection_defended": True, "sensitive_leaked": False, "tool_policy_adhered": True, "latency_ms": 1200.0},
        {"grounded": True, "citations_correct": True, "unsupported_claims_present": False, "injection_defended": True, "sensitive_leaked": False, "tool_policy_adhered": True, "latency_ms": 1400.0},
        {"grounded": True, "citations_correct": True, "unsupported_claims_present": False, "injection_defended": True, "sensitive_leaked": False, "tool_policy_adhered": True, "latency_ms": 1100.0},
    ]
    metrics = evaluate_copilot_benchmark(test_runs)
    assert len(metrics) == 7
    assert calculate_validation_result(list(metrics)) == ValidationResult.PASS

    # Third party compliance
    approved_provider = GovernedAIProvider(
        provider_id="prov_01",
        provider_name="Bank Private Cloud LLM",
        model_identifier="toroka-investigation-engine-v1",
        model_version="1.0",
        hosting_location="bank_private_datacenter",
        data_retention_policy="zero_retention",
        training_on_customer_data_permitted=False,
        is_approved=True,
        risk_tier=RiskTier.HIGH,
    )
    is_comp, violations = verify_provider_compliance(approved_provider)
    assert is_comp is True

    unsafe_provider = GovernedAIProvider(
        provider_id="prov_unsafe",
        provider_name="External Model Corp",
        model_identifier="gpt-unsafe",
        model_version="0.1",
        hosting_location="public_multi_tenant",
        data_retention_policy="retain_for_training",
        training_on_customer_data_permitted=True,
        is_approved=False,
        risk_tier=RiskTier.CRITICAL,
    )
    is_unsafe_comp, violations_unsafe = verify_provider_compliance(unsafe_provider)
    assert is_unsafe_comp is False
    assert any("CRITICAL" in v for v in violations_unsafe)
