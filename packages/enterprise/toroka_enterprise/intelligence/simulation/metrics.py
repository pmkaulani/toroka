from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import statistics
from typing import Any

from .domain import CandidateDetection, OutcomeLabel, SimulatedDetection


@dataclass(frozen=True)
class CaseOutcome:
    """Historical ground truth adjudication for a case."""

    case_id: str
    label: OutcomeLabel
    first_fraud_event_time: datetime | None = None
    adjudicated_at: datetime | None = None
    adjudicated_by: str | None = None
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "label": self.label.value,
            "first_fraud_event_time": (
                self.first_fraud_event_time.isoformat()
                if self.first_fraud_event_time
                else None
            ),
            "adjudicated_at": (
                self.adjudicated_at.isoformat() if self.adjudicated_at else None
            ),
            "adjudicated_by": self.adjudicated_by,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CaseOutcome:
        first_time = data.get("first_fraud_event_time")
        if isinstance(first_time, str):
            first_dt = datetime.fromisoformat(first_time)
        else:
            first_dt = first_time

        adj_time = data.get("adjudicated_at")
        if isinstance(adj_time, str):
            adj_dt = datetime.fromisoformat(adj_time)
        else:
            adj_dt = adj_time

        return cls(
            case_id=data["case_id"],
            label=OutcomeLabel(data.get("label", OutcomeLabel.UNLABELLED)),
            first_fraud_event_time=first_dt,
            adjudicated_at=adj_dt,
            adjudicated_by=data.get("adjudicated_by"),
            notes=data.get("notes"),
        )


@dataclass(frozen=True)
class SimulationMetrics:
    """Evaluation metrics for a simulated strategy replay."""

    total_cases_evaluated: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    mean_detection_delay_seconds: float | None
    median_detection_delay_seconds: float | None
    total_alerts: int
    alerted_cases: int
    alert_rate: float
    inconclusive_cases_alerted: int
    unlabelled_cases_alerted: int
    labelled_cases: int
    inconclusive_cases: int
    unlabelled_cases: int
    label_coverage_pct: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_cases_evaluated": self.total_cases_evaluated,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "mean_detection_delay_seconds": (
                round(self.mean_detection_delay_seconds, 2)
                if self.mean_detection_delay_seconds is not None
                else None
            ),
            "median_detection_delay_seconds": (
                round(self.median_detection_delay_seconds, 2)
                if self.median_detection_delay_seconds is not None
                else None
            ),
            "total_alerts": self.total_alerts,
            "alerted_cases": self.alerted_cases,
            "alert_rate": round(self.alert_rate, 4),
            "inconclusive_cases_alerted": self.inconclusive_cases_alerted,
            "unlabelled_cases_alerted": self.unlabelled_cases_alerted,
            "labelled_cases": self.labelled_cases,
            "inconclusive_cases": self.inconclusive_cases,
            "unlabelled_cases": self.unlabelled_cases,
            "label_coverage_pct": round(self.label_coverage_pct, 2),
        }


@dataclass(frozen=True)
class MetricsDelta:
    """Comparison delta between proposed and baseline strategies."""

    tp_diff: int
    fp_diff: int
    fn_diff: int
    tn_diff: int
    precision_diff: float
    recall_diff: float
    f1_diff: float
    detection_delay_diff_seconds: float | None
    alert_volume_diff: int
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "tp_diff": self.tp_diff,
            "fp_diff": self.fp_diff,
            "fn_diff": self.fn_diff,
            "tn_diff": self.tn_diff,
            "precision_diff": round(self.precision_diff, 4),
            "recall_diff": round(self.recall_diff, 4),
            "f1_diff": round(self.f1_diff, 4),
            "detection_delay_diff_seconds": (
                round(self.detection_delay_diff_seconds, 2)
                if self.detection_delay_diff_seconds is not None
                else None
            ),
            "alert_volume_diff": self.alert_volume_diff,
            "summary": self.summary,
        }


def calculate_metrics(
    outcomes: dict[str, CaseOutcome],
    case_detections: dict[str, list[CandidateDetection] | list[SimulatedDetection]],
) -> SimulationMetrics:
    """Calculate institutional simulation metrics over adjudicated ground truth cases.

    CRITICAL METHODOLOGICAL RULES:
    1. Only CONFIRMED_FRAUD and CONFIRMED_LEGITIMATE contribute to TP, FP, TN, FN.
    2. INCONCLUSIVE and UNLABELLED are excluded from precision/recall calculations to
       prevent polluting metrics with assumed outcomes.
    3. Detection delay is measured only on True Positive cases where first_fraud_event_time is recorded.
    """
    total_cases = len(outcomes)
    tp = 0
    fp = 0
    tn = 0
    fn = 0
    inconclusive_count = 0
    unlabelled_count = 0
    inconclusive_alerted = 0
    unlabelled_alerted = 0
    delays: list[float] = []

    total_alerts = 0
    alerted_cases_count = 0

    for case_id, outcome in outcomes.items():
        dets = case_detections.get(case_id, [])
        is_alerted = len(dets) > 0
        total_alerts += len(dets)
        if is_alerted:
            alerted_cases_count += 1

        label = outcome.label

        if label == OutcomeLabel.CONFIRMED_FRAUD:
            if is_alerted:
                tp += 1
                if outcome.first_fraud_event_time:
                    # Find earliest detection time
                    earliest_det = min(d.detected_at for d in dets)
                    # Delay in seconds
                    delay_sec = max(
                        0.0,
                        (earliest_det - outcome.first_fraud_event_time).total_seconds(),
                    )
                    delays.append(delay_sec)
            else:
                fn += 1

        elif label == OutcomeLabel.CONFIRMED_LEGITIMATE:
            if is_alerted:
                fp += 1
            else:
                tn += 1

        elif label == OutcomeLabel.INCONCLUSIVE:
            inconclusive_count += 1
            if is_alerted:
                inconclusive_alerted += 1

        else:  # UNLABELLED
            unlabelled_count += 1
            if is_alerted:
                unlabelled_alerted += 1

    labelled_cases = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * (precision * recall) / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    mean_delay = statistics.mean(delays) if delays else None
    median_delay = statistics.median(delays) if delays else None

    alert_rate = alerted_cases_count / total_cases if total_cases > 0 else 0.0
    coverage_pct = (labelled_cases / total_cases * 100.0) if total_cases > 0 else 0.0

    return SimulationMetrics(
        total_cases_evaluated=total_cases,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1_score=f1,
        mean_detection_delay_seconds=mean_delay,
        median_detection_delay_seconds=median_delay,
        total_alerts=total_alerts,
        alerted_cases=alerted_cases_count,
        alert_rate=alert_rate,
        inconclusive_cases_alerted=inconclusive_alerted,
        unlabelled_cases_alerted=unlabelled_alerted,
        labelled_cases=labelled_cases,
        inconclusive_cases=inconclusive_count,
        unlabelled_cases=unlabelled_count,
        label_coverage_pct=coverage_pct,
    )


def calculate_metrics_delta(
    baseline: SimulationMetrics,
    proposed: SimulationMetrics,
) -> MetricsDelta:
    """Compare a proposed strategy against baseline policy replay."""
    tp_diff = proposed.true_positives - baseline.true_positives
    fp_diff = proposed.false_positives - baseline.false_positives
    fn_diff = proposed.false_negatives - baseline.false_negatives
    tn_diff = proposed.true_negatives - baseline.true_negatives
    prec_diff = proposed.precision - baseline.precision
    rec_diff = proposed.recall - baseline.recall
    f1_diff = proposed.f1_score - baseline.f1_score
    alert_diff = proposed.total_alerts - baseline.total_alerts

    delay_diff: float | None = None
    if (
        proposed.mean_detection_delay_seconds is not None
        and baseline.mean_detection_delay_seconds is not None
    ):
        delay_diff = (
            proposed.mean_detection_delay_seconds
            - baseline.mean_detection_delay_seconds
        )

    # Institutional summary narrative
    parts: list[str] = []
    if tp_diff > 0:
        parts.append(f"Discovered {tp_diff} additional true positive fraud case(s)")
    elif tp_diff < 0:
        parts.append(f"Regressed by missing {abs(tp_diff)} previously detected fraud case(s)")

    if fp_diff < 0:
        parts.append(f"reduced false positive investigations by {abs(fp_diff)}")
    elif fp_diff > 0:
        parts.append(f"increased investigator alert noise with {fp_diff} additional false positive(s)")

    if prec_diff > 0.05:
        parts.append(f"improved precision by +{prec_diff * 100:.1f}%")
    elif prec_diff < -0.05:
        parts.append(f"degraded precision by {prec_diff * 100:.1f}%")

    if delay_diff is not None:
        if delay_diff < -60:
            parts.append(f"accelerated detection by {abs(delay_diff) / 60:.1f} minutes")
        elif delay_diff > 60:
            parts.append(f"delayed detection by {delay_diff / 60:.1f} minutes")

    if not parts:
        summary = "Performance is identical or comparable to baseline policy."
    else:
        summary = "; ".join(parts) + "."

    return MetricsDelta(
        tp_diff=tp_diff,
        fp_diff=fp_diff,
        fn_diff=fn_diff,
        tn_diff=tn_diff,
        precision_diff=prec_diff,
        recall_diff=rec_diff,
        f1_diff=f1_diff,
        detection_delay_diff_seconds=delay_diff,
        alert_volume_diff=alert_diff,
        summary=summary,
    )
