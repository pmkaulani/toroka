"""Tests for behavioral baselines, statistical calculations, deviations, and maturity states."""
from __future__ import annotations

import math
from datetime import datetime, timezone, timedelta
import pytest

from toroka_enterprise.intelligence.baselines import (
    BaselineDimension,
    BaselineWindow,
    MaturityState,
)
from toroka_enterprise.intelligence.statistics import (
    BaselineStatistics,
    calculate_statistics,
)
from toroka_enterprise.intelligence.deviation import (
    DeviationResult,
    median,
    calculate_deviation,
)
from toroka_enterprise.intelligence.profiles import BehavioralProfile
from toroka_enterprise.intelligence.anomalies import (
    AnomalySeverity,
    BehavioralAnomaly,
)
from toroka_enterprise.intelligence.scoring import severity_from_deviation


def test_baseline_window_valid_and_invalid():
    now = datetime.now(timezone.utc)
    w = BaselineWindow(start=now, end=now + timedelta(days=30))
    assert w.duration_seconds == 30 * 86400

    with pytest.raises(ValueError, match="positive duration"):
        BaselineWindow(start=now, end=now)

    with pytest.raises(ValueError, match="positive duration"):
        BaselineWindow(start=now, end=now - timedelta(hours=1))


def test_calculate_statistics_even_and_odd():
    # Odd count
    stats_odd = calculate_statistics([1.0, 2.0, 3.0, 4.0, 5.0])
    assert stats_odd.count == 5
    assert stats_odd.mean == 3.0
    assert stats_odd.median == 3.0
    assert stats_odd.minimum == 1.0
    assert stats_odd.maximum == 5.0
    assert math.isclose(stats_odd.standard_deviation, math.sqrt(2.0))

    # Even count
    stats_even = calculate_statistics([10.0, 20.0, 30.0, 40.0])
    assert stats_even.count == 4
    assert stats_even.mean == 25.0
    assert stats_even.median == 25.0

    # Empty list raises ValueError
    with pytest.raises(ValueError, match="empty values"):
        calculate_statistics([])


def test_median_helper():
    assert median([5.0]) == 5.0
    assert median([1.0, 9.0]) == 5.0
    assert median([3.0, 1.0, 2.0]) == 2.0

    with pytest.raises(ValueError, match="empty"):
        median([])


def test_mad_deviation_and_outlier_robustness():
    # Normal baseline with varied daily actions so MAD > 0
    baseline = [3.0, 4.0, 5.0, 6.0, 7.0, 4.0, 5.0, 6.0, 5.0, 6.0]

    # Normal observation (within baseline range)
    dev_normal = calculate_deviation(5.0, baseline)
    assert not dev_normal.is_anomalous
    assert dev_normal.baseline_median == 5.0
    assert dev_normal.modified_z_score is not None
    assert abs(dev_normal.modified_z_score) < 3.5

    # Extreme observation (outlier spike)
    dev_spike = calculate_deviation(50.0, baseline)
    assert dev_spike.is_anomalous
    assert dev_spike.modified_z_score is not None
    assert dev_spike.modified_z_score > 3.5

    # Robustness: adding an extreme historic spike to the baseline should NOT
    # heavily skew MAD the way it skews mean and standard deviation.
    skewed_baseline = baseline + [1000.0]  # Single huge outlier
    stats_skewed = calculate_statistics(skewed_baseline)
    dev_skewed = calculate_deviation(5.0, skewed_baseline)

    # Standard deviation is inflated dramatically by 1000.0
    assert stats_skewed.standard_deviation > 200.0
    # But median and MAD remain robust and low
    assert dev_skewed.baseline_median == 5.0
    assert dev_skewed.median_absolute_deviation <= 2.0


def test_mad_deviation_zero_variance():
    # When all baseline observations are identical, MAD is 0
    zero_var_baseline = [10.0, 10.0, 10.0, 10.0]
    dev_same = calculate_deviation(10.0, zero_var_baseline)
    assert dev_same.median_absolute_deviation == 0.0
    assert dev_same.modified_z_score is None
    assert not dev_same.is_anomalous

    dev_diff = calculate_deviation(11.0, zero_var_baseline)
    assert dev_diff.is_anomalous


def test_behavioral_profile_maturity_states():
    now = datetime.now(timezone.utc)
    prof = BehavioralProfile(
        installation_id="inst_alpha",
        subject_id="emp_001",
        subject_type="employee",
        observation_start=now,
        observation_end=now + timedelta(days=30),
        sample_count=5,
    )
    assert not prof.mature
    assert prof.maturity_state == MaturityState.INSUFFICIENT

    prof.sample_count = 15
    assert not prof.mature
    assert prof.maturity_state == MaturityState.DEVELOPING

    prof.sample_count = 20
    assert prof.mature
    assert prof.maturity_state == MaturityState.MATURE


def test_severity_from_deviation_maturity_damping():
    # Immature baseline must NEVER produce high severity findings
    assert severity_from_deviation(10.0, mature=False) == AnomalySeverity.LOW
    assert severity_from_deviation(5.0, mature=False) == AnomalySeverity.LOW

    # Mature baseline scales severity based on modified z-score magnitude
    assert severity_from_deviation(2.5, mature=True) == AnomalySeverity.LOW
    assert severity_from_deviation(4.5, mature=True) == AnomalySeverity.MEDIUM
    assert severity_from_deviation(7.0, mature=True) == AnomalySeverity.HIGH
    assert severity_from_deviation(-8.0, mature=True) == AnomalySeverity.HIGH


def test_behavioral_anomaly_confidence_bounds():
    now = datetime.now(timezone.utc)
    anom = BehavioralAnomaly(
        anomaly_id="anom_1",
        installation_id="inst_1",
        subject_id="emp_1",
        dimension="daily_activity",
        observed_value=85.0,
        expected_value=5.0,
        deviation=12.5,
        severity=AnomalySeverity.HIGH,
        confidence=0.95,
        explanation="High activity spike",
        baseline_sample_count=30,
        baseline_mature=True,
    )
    assert anom.confidence == 0.95

    with pytest.raises(ValueError, match="confidence must be between 0 and 1"):
        BehavioralAnomaly(
            anomaly_id="anom_2",
            installation_id="inst_1",
            subject_id="emp_1",
            dimension="daily_activity",
            observed_value=85.0,
            expected_value=5.0,
            deviation=12.5,
            severity=AnomalySeverity.HIGH,
            confidence=1.5,
            explanation="Invalid confidence",
            baseline_sample_count=30,
            baseline_mature=True,
        )
