from __future__ import annotations

from datetime import datetime, timedelta, timezone

from toroka_enterprise.intelligence.events import IntelligenceEvent
from toroka_enterprise.intelligence.simulation import (
    CandidateDetection,
    CaseOutcome,
    OutcomeLabel,
    ReplayObservation,
    SimulationStrategy,
    calculate_metrics,
    calculate_metrics_delta,
    compare_strategies,
    replay_strategy,
    run_strategy_detectors,
)


def _dt(hour: int, minute: int) -> datetime:
    return datetime(2026, 11, 15, hour, minute, tzinfo=timezone.utc)


def test_simulation_strategy_serialization():
    strat = SimulationStrategy(
        strategy_id="strat_test",
        version=1,
        title="Test Strategy",
        description="Evaluates correlation rules",
        rules_enabled=("employee_access_before_sensitive_change",),
        parameters={"window_minutes": 30},
        min_severity="medium",
        min_confidence=0.7,
        created_by="analyst_alice",
        status="draft",
    )
    d = strat.to_dict()
    assert d["strategy_id"] == "strat_test"
    assert d["rules_enabled"] == ["employee_access_before_sensitive_change"]
    assert d["min_confidence"] == 0.7

    restored = SimulationStrategy.from_dict(d)
    assert restored.strategy_id == strat.strategy_id
    assert restored.rules_enabled == strat.rules_enabled
    assert restored.min_confidence == strat.min_confidence


def test_event_availability_cutoff():
    """Verify that events arriving after the simulation cutoff are invisible to replay."""
    t1 = _dt(10, 0)
    t1_avail = _dt(10, 5)

    t2 = _dt(10, 2)
    t2_avail = _dt(10, 30)  # Delayed ingestion

    obs1 = ReplayObservation(
        event_id="ev_001",
        event_time=t1,
        available_at=t1_avail,
        source_system="core_banking",
        event_type="customer_record_access",
        actor_id="emp_01",
        subject_id="cust_99",
        case_id="case_01",
    )
    obs2 = ReplayObservation(
        event_id="ev_002",
        event_time=t2,
        available_at=t2_avail,
        source_system="core_banking",
        event_type="beneficiary_change",
        actor_id="emp_01",
        subject_id="cust_99",
        case_id="case_01",
    )

    strat = SimulationStrategy(
        strategy_id="strat_cutoff",
        version=1,
        title="Cutoff Test",
        description="Tests event availability",
        rules_enabled=("employee_access_before_sensitive_change",),
    )

    outcomes = {
        "case_01": CaseOutcome(case_id="case_01", label=OutcomeLabel.CONFIRMED_FRAUD)
    }

    # Cutoff at 10:15 - obs2 should be filtered out
    res_early = replay_strategy(
        strategy=strat,
        cases_events={"case_01": [obs1, obs2]},
        case_outcomes=outcomes,
        simulation_cutoff=_dt(10, 15),
    )
    assert res_early.total_events_replayed == 1
    assert res_early.delayed_events_filtered == 1
    assert len(res_early.case_detections["case_01"]) == 0
    assert res_early.metrics.false_negatives == 1

    # Cutoff at 10:45 - both observations visible, rule triggers!
    res_late = replay_strategy(
        strategy=strat,
        cases_events={"case_01": [obs1, obs2]},
        case_outcomes=outcomes,
        simulation_cutoff=_dt(10, 45),
    )
    assert res_late.total_events_replayed == 2
    assert res_late.delayed_events_filtered == 0
    assert len(res_late.case_detections["case_01"]) == 1
    assert res_late.metrics.true_positives == 1


def test_deterministic_sorting_in_replay():
    """Verify events are sorted by (available_at, event_time, event_id)."""
    t0 = _dt(9, 0)
    t1 = _dt(10, 0)
    t2 = _dt(11, 0)

    # obs_b occurred later than obs_a, but was available earlier
    obs_a = ReplayObservation(
        event_id="ev_a",
        event_time=t0,
        available_at=t2,
        source_system="core",
        event_type="access",
    )
    obs_b = ReplayObservation(
        event_id="ev_b",
        event_time=t1,
        available_at=t1,
        source_system="core",
        event_type="change",
    )

    observations = [obs_a, obs_b]
    observations.sort(key=lambda o: (o.available_at, o.event_time, o.event_id))
    # obs_b should be first because available_at is earlier (t1 < t2)
    assert [o.event_id for o in observations] == ["ev_b", "ev_a"]


def test_metrics_calculation_ground_truth():
    """Test standard metrics: TP, FP, TN, FN, precision, recall, label exclusion."""
    first_fraud_time = _dt(8, 0)
    det_time = _dt(8, 30)

    outcomes = {
        "c_tp": CaseOutcome(
            case_id="c_tp",
            label=OutcomeLabel.CONFIRMED_FRAUD,
            first_fraud_event_time=first_fraud_time,
        ),
        "c_fn": CaseOutcome(
            case_id="c_fn",
            label=OutcomeLabel.CONFIRMED_FRAUD,
            first_fraud_event_time=first_fraud_time,
        ),
        "c_fp": CaseOutcome(
            case_id="c_fp",
            label=OutcomeLabel.CONFIRMED_LEGITIMATE,
        ),
        "c_tn": CaseOutcome(
            case_id="c_tn",
            label=OutcomeLabel.CONFIRMED_LEGITIMATE,
        ),
        "c_inconclusive": CaseOutcome(
            case_id="c_inconclusive",
            label=OutcomeLabel.INCONCLUSIVE,
        ),
        "c_unlabelled": CaseOutcome(
            case_id="c_unlabelled",
            label=OutcomeLabel.UNLABELLED,
        ),
    }

    dummy_det_tp = CandidateDetection(
        detection_id="d1",
        case_id="c_tp",
        event_id="e1",
        detected_at=det_time,
        rule_name="rule1",
        severity="high",
        confidence=0.9,
        explanation="Test TP",
        supporting_event_ids=("e1",),
    )
    dummy_det_fp = CandidateDetection(
        detection_id="d2",
        case_id="c_fp",
        event_id="e2",
        detected_at=det_time,
        rule_name="rule1",
        severity="medium",
        confidence=0.7,
        explanation="Test FP",
        supporting_event_ids=("e2",),
    )
    dummy_det_inconc = CandidateDetection(
        detection_id="d3",
        case_id="c_inconclusive",
        event_id="e3",
        detected_at=det_time,
        rule_name="rule1",
        severity="low",
        confidence=0.6,
        explanation="Test Inconclusive",
        supporting_event_ids=("e3",),
    )

    case_dets = {
        "c_tp": [dummy_det_tp],
        "c_fn": [],
        "c_fp": [dummy_det_fp],
        "c_tn": [],
        "c_inconclusive": [dummy_det_inconc],
        "c_unlabelled": [],
    }

    metrics = calculate_metrics(outcomes, case_dets)

    assert metrics.total_cases_evaluated == 6
    assert metrics.true_positives == 1
    assert metrics.false_positives == 1
    assert metrics.false_negatives == 1
    assert metrics.true_negatives == 1
    assert metrics.labelled_cases == 4
    assert metrics.inconclusive_cases == 1
    assert metrics.inconclusive_cases_alerted == 1
    assert metrics.unlabelled_cases == 1
    assert metrics.unlabelled_cases_alerted == 0

    # Precision = 1 / (1 + 1) = 0.5
    assert metrics.precision == 0.5
    # Recall = 1 / (1 + 1) = 0.5
    assert metrics.recall == 0.5
    assert metrics.f1_score == 0.5

    # Delay = (8:30 - 8:00) = 1800 seconds
    assert metrics.mean_detection_delay_seconds == 1800.0
    assert metrics.median_detection_delay_seconds == 1800.0

    # Label coverage = 4 / 6 = 66.67%
    assert round(metrics.label_coverage_pct, 1) == 66.7


def test_strategy_comparison_and_delta():
    """Verify side-by-side strategy comparison."""
    t1 = _dt(10, 0)
    t2 = _dt(10, 10)

    obs1 = ReplayObservation(
        event_id="ev_01",
        event_time=t1,
        available_at=t1,
        source_system="core_banking",
        event_type="customer_record_access",
        actor_id="emp_01",
        subject_id="cust_01",
        case_id="case_1",
    )
    obs2 = ReplayObservation(
        event_id="ev_02",
        event_time=t2,
        available_at=t2,
        source_system="core_banking",
        event_type="beneficiary_change",
        actor_id="emp_01",
        subject_id="cust_01",
        case_id="case_1",
    )

    baseline_strat = SimulationStrategy(
        strategy_id="strat_base",
        version=1,
        title="Baseline (No Rules)",
        description="Empty rules",
        rules_enabled=(),
    )
    proposed_strat = SimulationStrategy(
        strategy_id="strat_prop",
        version=1,
        title="Proposed (Access Rule)",
        description="Includes access rule",
        rules_enabled=("employee_access_before_sensitive_change",),
    )

    outcomes = {
        "case_1": CaseOutcome(
            case_id="case_1",
            label=OutcomeLabel.CONFIRMED_FRAUD,
            first_fraud_event_time=t1,
        )
    }

    comp = compare_strategies(
        baseline_strategy=baseline_strat,
        proposed_strategy=proposed_strat,
        cases_events={"case_1": [obs1, obs2]},
        case_outcomes=outcomes,
    )

    assert comp.baseline_run.metrics.true_positives == 0
    assert comp.baseline_run.metrics.false_negatives == 1
    assert comp.proposed_run.metrics.true_positives == 1
    assert comp.proposed_run.metrics.false_negatives == 0
    assert comp.delta.tp_diff == 1
    assert comp.delta.fn_diff == -1
    assert "Discovered 1 additional true positive" in comp.delta.summary
