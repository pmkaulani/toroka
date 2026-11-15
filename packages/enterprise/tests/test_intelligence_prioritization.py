"""Tests for investigation prioritization, source deduplication, and model governance."""
from __future__ import annotations

import pytest
from toroka_enterprise.intelligence.signals import CorrelationSignal, SignalSeverity
from toroka_enterprise.intelligence.anomalies import BehavioralAnomaly, AnomalySeverity
from toroka_enterprise.intelligence.prioritization import (
    InvestigationPriority,
    calculate_priority,
)
from toroka_enterprise.intelligence.deviation import calculate_deviation
from toroka_enterprise.intelligence.scoring import severity_from_deviation
from toroka_enterprise.intelligence.governance import (
    ModelStatus,
    DetectionMethod,
)
from toroka_enterprise.intelligence.detection import (
    DetectionContext,
    DetectionResult,
    Detector,
)
from toroka_enterprise.intelligence.sources import (
    SourceSystem,
    get_source_reliability,
    DEFAULT_SOURCE_RELIABILITIES,
)


def test_priority_calculation_signals_and_anomalies():
    signal = CorrelationSignal(
        signal_id="sig_1",
        signal_type="temporal_reversal",
        severity=SignalSeverity.HIGH,
        title="Payment Reversal Shortly After Employee Access",
        explanation="Staff accessed account 2 minutes before reversal was initiated.",
        event_ids=("evt_1", "evt_2"),
        confidence=0.85,
        evidence=({"source_system": "core_banking"}, {"source_system": "iam"}),
    )

    anomaly = BehavioralAnomaly(
        anomaly_id="anom_1",
        installation_id="inst_bank",
        subject_id="emp_401",
        dimension="beneficiary_changes",
        observed_value=22.0,
        expected_value=2.0,
        deviation=8.5,
        severity=AnomalySeverity.HIGH,
        confidence=0.9,
        explanation="22 beneficiary modifications in one shift vs normal 2.",
        baseline_sample_count=25,
        baseline_mature=True,
    )

    priority = calculate_priority(
        signals=[signal],
        anomalies=[anomaly],
    )

    # Base high signal: 25 + 0.85*10 = 33.5
    # High mature anomaly: 20
    # Independent sources: core_banking + iam (2 sources) -> +5 bonus
    # Total score ~ 58.5
    assert priority.priority_score >= 50.0
    assert priority.requires_review
    assert priority.independent_sources_count == 2
    assert any("Established behavioral deviation" in r for r in priority.reasons)
    assert any("Correlation signal" in r for r in priority.reasons)


def test_adversarial_same_event_multiple_systems_deduplication():
    """Adversarial Test 3: Same event ingested through multiple systems (e.g. SIEM copy of IAM log)

    must NOT inflate the independent corroboration score.
    """
    # Signal with 3 copies of evidence all citing the same SIEM source
    siem_signal = CorrelationSignal(
        signal_id="sig_siem_multi",
        signal_type="auth_burst",
        severity=SignalSeverity.MEDIUM,
        title="Multiple SIEM Log Entries for Single Event",
        explanation="Replicated SIEM feeds for single login.",
        event_ids=("evt_s1", "evt_s2", "evt_s3"),
        confidence=0.7,
        evidence=(
            {"source_system": "siem", "raw_id": "log1"},
            {"source_system": "siem", "raw_id": "log2"},
            {"source_system": "siem", "raw_id": "log3"},
        ),
    )

    priority = calculate_priority(
        signals=[siem_signal],
        anomalies=[],
    )

    # Only 1 unique source system ("siem")
    assert priority.independent_sources_count == 1
    # No multi-source corroboration bonus added
    assert not any("Corroborated across" in r for r in priority.reasons)


def test_adversarial_new_employee_unusual_activity():
    """Adversarial Test 4: A new employee with limited history performs unusual activity.

    Baseline maturity must be DEVELOPING or INSUFFICIENT, capping severity at LOW,
    and priority reason must state 'Limited-history', preventing wrongful accusation.
    """
    immature_anomaly = BehavioralAnomaly(
        anomaly_id="anom_newbie",
        installation_id="inst_bank",
        subject_id="emp_new_hire",
        dimension="daily_activity",
        observed_value=40.0,
        expected_value=10.0,
        deviation=6.5,
        severity=severity_from_deviation(6.5, mature=False),  # Returns LOW
        confidence=0.4,
        explanation="New employee performed 40 transactions on day 3.",
        baseline_sample_count=3,
        baseline_mature=False,
    )

    assert immature_anomaly.severity == AnomalySeverity.LOW

    priority = calculate_priority(
        signals=[],
        anomalies=[immature_anomaly],
    )

    assert priority.priority_score <= 10.0
    assert not priority.requires_review
    assert any("Limited-history behavioral deviation" in r for r in priority.reasons)


def test_adversarial_legitimate_high_volume_employee():
    """Adversarial Test 5: A legitimate high-volume operations employee performs a large batch.

    Because their mature baseline reflects high volumes, deviation remains low.
    """
    high_volume_baseline = [450.0, 500.0, 480.0, 520.0, 490.0, 510.0, 470.0, 530.0, 500.0, 495.0] * 3  # 30 samples
    dev = calculate_deviation(550.0, high_volume_baseline)

    # Within reasonable variance for a 500-transaction/day employee
    assert not dev.is_anomalous
    sev = severity_from_deviation(dev.modified_z_score or 0.0, mature=True)
    assert sev == AnomalySeverity.LOW


def test_adversarial_customer_support_explanation_as_contradiction():
    """Adversarial Test 6: A customer support ticket explains an otherwise suspicious pattern.

    The contradiction is surfaced in the prioritization breakdown.
    """
    signal = CorrelationSignal(
        signal_id="sig_supp",
        signal_type="customer_account_change",
        severity=SignalSeverity.MEDIUM,
        title="Account Contact Change",
        explanation="Customer phone number changed by employee.",
        event_ids=("evt_c1",),
        confidence=0.8,
        alternative_explanations=("Customer submitted verified ticket CRM-4410",),
    )

    priority = calculate_priority(
        signals=[signal],
        anomalies=[],
        unresolved_contradictions=1,
    )

    assert priority.unresolved_contradictions == 1
    assert any("competing explanation(s) or contradiction(s)" in r for r in priority.reasons)


def test_source_reliability_registry():
    core = get_source_reliability(SourceSystem.CORE_BANKING.value)
    assert core.weight == 1.0
    assert core.is_authoritative

    siem = get_source_reliability("SIEM")
    assert siem.weight == 0.80
    assert not siem.is_authoritative

    unknown = get_source_reliability("unknown_external_vendor")
    assert unknown.weight == 0.5


def test_model_governance_and_future_ml_detector_boundary():
    # Governance metadata
    method = DetectionMethod(
        method_id="det_stat_mad_v1",
        version="1.0.0",
        status=ModelStatus.DETERMINISTIC,
        description="Deterministic MAD deviation detector",
        validation_reference="VAL-2026-STAT",
        limitations=("Requires 20 observations for mature baseline",),
    )
    assert method.status == ModelStatus.DETERMINISTIC
    assert method.version == "1.0.0"

    # Future ML detector conforming to the Detector protocol
    class MockStatisticalDetector:
        detector_id = "mock_ml_detector"
        detector_version = "0.9.0"

        def detect(self, context: DetectionContext) -> DetectionResult:
            return DetectionResult(
                detector_id=self.detector_id,
                detector_version=self.detector_version,
                signals=(),
                evidence_ids=("ev_1", "ev_2"),
                explanation="Mock anomaly detected through protocol",
                limitations=("Experimental prototype",),
            )

    det: Detector = MockStatisticalDetector()
    ctx = DetectionContext(installation_id="inst_1", subject_id="emp_test")
    res = det.detect(ctx)
    assert res.detector_id == "mock_ml_detector"
    assert "ev_1" in res.evidence_ids
