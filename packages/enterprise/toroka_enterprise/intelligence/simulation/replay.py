from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
import uuid

from .domain import (
    CandidateDetection,
    ReplayObservation,
    SimulatedDetection,
    SimulationStrategy,
)
from .metrics import (
    CaseOutcome,
    MetricsDelta,
    SimulationMetrics,
    calculate_metrics,
    calculate_metrics_delta,
)
from .runner import run_strategy_detectors


@dataclass(frozen=True)
class SimulationRunResult:
    """Result of replaying a single detection strategy over historical case data."""

    simulation_id: str
    strategy_id: str
    strategy_version: int
    evaluated_at: datetime
    simulation_cutoff: datetime | None
    metrics: SimulationMetrics
    case_detections: dict[str, list[SimulatedDetection]]
    total_events_replayed: int
    delayed_events_filtered: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "simulation_id": self.simulation_id,
            "strategy_id": self.strategy_id,
            "strategy_version": self.strategy_version,
            "evaluated_at": self.evaluated_at.isoformat(),
            "simulation_cutoff": (
                self.simulation_cutoff.isoformat()
                if self.simulation_cutoff
                else None
            ),
            "metrics": self.metrics.to_dict(),
            "case_detections": {
                c_id: [d.to_dict() for d in dets]
                for c_id, dets in self.case_detections.items()
            },
            "total_events_replayed": self.total_events_replayed,
            "delayed_events_filtered": self.delayed_events_filtered,
        }


@dataclass(frozen=True)
class SimulationComparisonResult:
    """Side-by-side comparison between proposed strategy and baseline policy."""

    comparison_id: str
    baseline_run: SimulationRunResult
    proposed_run: SimulationRunResult
    delta: MetricsDelta

    def to_dict(self) -> dict[str, Any]:
        return {
            "comparison_id": self.comparison_id,
            "baseline_run": self.baseline_run.to_dict(),
            "proposed_run": self.proposed_run.to_dict(),
            "delta": self.delta.to_dict(),
        }


def replay_strategy(
    strategy: SimulationStrategy,
    cases_events: dict[str, list[ReplayObservation]],
    case_outcomes: dict[str, CaseOutcome],
    simulation_cutoff: datetime | None = None,
    installation_id: str = "toroka-simulation",
    simulation_id: str | None = None,
) -> SimulationRunResult:
    """Replay a counterfactual detection strategy deterministically across historical cases.

    Enforces temporal availability: events where `available_at > simulation_cutoff`
    are invisible to the strategy at simulation time.
    Orders events deterministically by `(available_at, event_time, event_id)`.
    """
    sim_id = simulation_id or f"sim_{uuid.uuid4().hex[:12]}"
    now_utc = datetime.now(timezone.utc)

    total_replayed = 0
    delayed_filtered = 0
    case_sim_detections: dict[str, list[SimulatedDetection]] = {}

    for case_id, obs_list in cases_events.items():
        # 1. Filter by availability cutoff
        if simulation_cutoff is not None:
            visible_obs = [
                obs for obs in obs_list if obs.available_at <= simulation_cutoff
            ]
            delayed_filtered += len(obs_list) - len(visible_obs)
        else:
            visible_obs = list(obs_list)

        # 2. Deterministic sorting: (available_at, event_time, event_id)
        visible_obs.sort(
            key=lambda o: (o.available_at, o.event_time, o.event_id)
        )

        # 3. Convert to IntelligenceEvent sequence
        events = [obs.to_intelligence_event(installation_id) for obs in visible_obs]
        total_replayed += len(events)

        # 4. Run detectors
        candidates = run_strategy_detectors(strategy, case_id, events)

        # 5. Enrich with strategy provenance
        sim_dets = [
            SimulatedDetection(
                detection_id=c.detection_id,
                strategy_id=strategy.strategy_id,
                strategy_version=strategy.version,
                case_id=case_id,
                event_id=c.event_id,
                detected_at=c.detected_at,
                rule_name=c.rule_name,
                severity=c.severity,
                confidence=c.confidence,
                explanation=c.explanation,
                supporting_event_ids=tuple(c.supporting_event_ids),
            )
            for c in candidates
        ]
        case_sim_detections[case_id] = sim_dets

    # Ensure all outcome cases are represented in case_sim_detections even if they had no events
    for case_id in case_outcomes:
        if case_id not in case_sim_detections:
            case_sim_detections[case_id] = []

    # 6. Calculate metrics
    metrics = calculate_metrics(case_outcomes, case_sim_detections)

    return SimulationRunResult(
        simulation_id=sim_id,
        strategy_id=strategy.strategy_id,
        strategy_version=strategy.version,
        evaluated_at=now_utc,
        simulation_cutoff=simulation_cutoff,
        metrics=metrics,
        case_detections=case_sim_detections,
        total_events_replayed=total_replayed,
        delayed_events_filtered=delayed_filtered,
    )


def compare_strategies(
    baseline_strategy: SimulationStrategy,
    proposed_strategy: SimulationStrategy,
    cases_events: dict[str, list[ReplayObservation]],
    case_outcomes: dict[str, CaseOutcome],
    simulation_cutoff: datetime | None = None,
    installation_id: str = "toroka-simulation",
) -> SimulationComparisonResult:
    """Execute historical replay of both baseline and proposed strategies on identical cohorts."""
    comparison_id = f"cmp_{uuid.uuid4().hex[:12]}"

    base_run = replay_strategy(
        strategy=baseline_strategy,
        cases_events=cases_events,
        case_outcomes=case_outcomes,
        simulation_cutoff=simulation_cutoff,
        installation_id=installation_id,
        simulation_id=f"{comparison_id}_base",
    )

    prop_run = replay_strategy(
        strategy=proposed_strategy,
        cases_events=cases_events,
        case_outcomes=case_outcomes,
        simulation_cutoff=simulation_cutoff,
        installation_id=installation_id,
        simulation_id=f"{comparison_id}_prop",
    )

    delta = calculate_metrics_delta(base_run.metrics, prop_run.metrics)

    return SimulationComparisonResult(
        comparison_id=comparison_id,
        baseline_run=base_run,
        proposed_run=prop_run,
        delta=delta,
    )
