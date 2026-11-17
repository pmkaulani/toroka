"""Tests for Toroka Enterprise Quantitative Model Risk (OCC SR 11-7 / Fed SR 15-18)."""
from __future__ import annotations

import math
import pytest
from toroka_enterprise.governance.champion_challenger import (
    ModelPerformanceMetrics,
    PromotionDecision,
    evaluate_challenger_promotion,
)
from toroka_enterprise.governance.quantitative_risk import (
    DriftSeverity,
    compute_disparate_impact,
    compute_ks_statistic,
    compute_psi,
    compute_wasserstein_distance,
    evaluate_model_risk_comprehensive,
)


def test_psi_identical_distributions():
    baseline = [float(i) for i in range(100)]
    current = [float(i) for i in range(100)]

    summary = compute_psi(baseline, current, num_bins=10)
    assert summary.score >= 0.0
    assert summary.score < 0.01
    assert summary.severity == DriftSeverity.STABLE
    assert summary.requires_mitigation is False
    assert len(summary.bin_details) == 10


def test_psi_moderate_drift():
    # Moderate mean shift
    baseline = [float(i) for i in range(200)]
    # Shift current by roughly 10-15% of distribution range
    current = [float(i + 25) for i in range(200)]

    summary = compute_psi(baseline, current, num_bins=10)
    assert summary.score > 0.05
    assert summary.severity in (DriftSeverity.MODERATE, DriftSeverity.SIGNIFICANT)


def test_psi_critical_drift():
    # Drastic distribution divergence
    baseline = [0.1 * i for i in range(100)]
    current = [10.0 + 0.1 * i for i in range(100)]

    summary = compute_psi(baseline, current, num_bins=10)
    assert summary.score >= 0.25
    assert summary.severity == DriftSeverity.SIGNIFICANT
    assert summary.requires_mitigation is True


def test_ks_statistic_2sample():
    baseline = [1.0, 2.0, 3.0, 4.0, 5.0]
    current = [1.0, 2.0, 3.0, 4.0, 5.0]

    res = compute_ks_statistic(baseline, current)
    assert res.statistic == 0.0
    assert res.is_drift_detected is False

    # Staggered shift
    shifted = [10.0, 20.0, 30.0, 40.0, 50.0]
    res_shifted = compute_ks_statistic(baseline, shifted)
    assert res_shifted.statistic == 1.0


def test_wasserstein_1d_distance():
    dist_a = [0.0, 1.0, 2.0]
    dist_b = [0.0, 1.0, 2.0]
    assert compute_wasserstein_distance(dist_a, dist_b) == 0.0

    # Shifting by +1 unit everywhere increases W1 by exactly 1.0
    dist_c = [1.0, 2.0, 3.0]
    w1 = compute_wasserstein_distance(dist_a, dist_c)
    assert math.isclose(w1, 1.0, rel_tol=1e-5)


def test_disparate_impact_eeoc_4_5ths_rule():
    # Reference group A: 80% favorable selection rate
    # Group B: 70% -> DIR = 70/80 = 0.875 (Compliant)
    # Group C: 40% -> DIR = 40/80 = 0.500 (Adverse Impact < 0.80)
    subgroups = {
        "tier_prime": [True] * 80 + [False] * 20,
        "tier_standard": [True] * 70 + [False] * 30,
        "tier_subprime": [True] * 40 + [False] * 60,
    }

    summary = compute_disparate_impact(subgroups, reference_group="tier_prime")
    assert summary.reference_group == "tier_prime"
    assert summary.has_adverse_impact is True

    sub_map = {s.group_name: s for s in summary.subgroups}
    assert sub_map["tier_prime"].disparate_impact_ratio == 1.0
    assert sub_map["tier_standard"].is_adverse_impact is False
    assert sub_map["tier_subprime"].is_adverse_impact is True
    assert math.isclose(sub_map["tier_subprime"].disparate_impact_ratio, 0.50, rel_tol=1e-3)


def test_comprehensive_model_risk_evaluation():
    base = [float(i) for i in range(100)]
    curr_stable = [float(i) for i in range(100)]

    assessment = evaluate_model_risk_comprehensive(
        component_id="detector-layer1",
        component_version="1.0.0",
        evaluation_id="eval-comp-01",
        baseline_scores=base,
        current_scores=curr_stable,
    )
    assert assessment.is_compliant is True
    assert len(assessment.governance_findings) == 0

    # Drastic shift fails compliance
    curr_drift = [float(i + 50) for i in range(100)]
    assessment_drift = evaluate_model_risk_comprehensive(
        component_id="detector-layer1",
        component_version="1.0.0",
        evaluation_id="eval-comp-02",
        baseline_scores=base,
        current_scores=curr_drift,
    )
    assert assessment_drift.is_compliant is False
    assert any("CRITICAL DRIFT" in f for f in assessment_drift.governance_findings)


def test_champion_challenger_shadow_promotion_gate():
    champ = ModelPerformanceMetrics(
        model_role="CHAMPION",
        component_id="risk-scorer",
        component_version="1.0.0",
        sample_size=500,
        true_positives=90,
        false_positives=10,  # FDR = 10/100 = 10.0%
        true_negatives=390,
        false_negatives=10,  # Recall = 90/100 = 90.0%
        latency_ms_p50=12.0,
        latency_ms_p95=35.0,
    )

    # 1. Non-inferior challenger -> APPROVED
    chall_good = ModelPerformanceMetrics(
        model_role="CHALLENGER",
        component_id="risk-scorer",
        component_version="1.1.0",
        sample_size=500,
        true_positives=92,
        false_positives=9,   # FDR = 9/101 = 8.91%
        true_negatives=391,
        false_negatives=8,
        latency_ms_p50=11.0,
        latency_ms_p95=32.0,
    )
    res_good = evaluate_challenger_promotion(champ, chall_good)
    assert res_good.is_promotable is True
    assert res_good.decision == PromotionDecision.APPROVED_FOR_PROMOTION

    # 2. FDR regression > 2% -> REJECTED_EXCESSIVE_FDR
    chall_high_fdr = ModelPerformanceMetrics(
        model_role="CHALLENGER",
        component_id="risk-scorer",
        component_version="1.2.0",
        sample_size=500,
        true_positives=90,
        false_positives=25,  # FDR = 25/115 = 21.74% (+11.74% > 2% cap)
        true_negatives=375,
        false_negatives=10,
        latency_ms_p50=12.0,
        latency_ms_p95=35.0,
    )
    res_fdr = evaluate_challenger_promotion(champ, chall_high_fdr)
    assert res_fdr.is_promotable is False
    assert res_fdr.decision == PromotionDecision.REJECTED_EXCESSIVE_FDR

    # 3. Latency SLA violation -> REJECTED_LATENCY_VIOLATION
    chall_slow = ModelPerformanceMetrics(
        model_role="CHALLENGER",
        component_id="risk-scorer",
        component_version="1.3.0",
        sample_size=500,
        true_positives=92,
        false_positives=9,
        true_negatives=391,
        false_negatives=8,
        latency_ms_p50=180.0,
        latency_ms_p95=320.0,  # Exceeds 250ms SLA
    )
    res_lat = evaluate_challenger_promotion(champ, chall_slow, max_p95_latency_ms=250.0)
    assert res_lat.is_promotable is False
    assert res_lat.decision == PromotionDecision.REJECTED_LATENCY_VIOLATION
