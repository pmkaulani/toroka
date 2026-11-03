from __future__ import annotations

from dataclasses import dataclass, asdict
from collections import defaultdict
import hashlib
from typing import Iterable


@dataclass(frozen=True, slots=True)
class EvaluationCase:
    case_id: str
    campaign_id: str
    actual_scam: bool
    predicted_risk: bool
    language: str = "undetermined"
    tactic: str = "other"


@dataclass(slots=True)
class EvaluationReport:
    samples: int
    campaigns: int
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    precision: float | None
    recall: float | None
    specificity: float | None
    false_positive_rate: float | None
    f1: float | None
    by_language: dict[str, dict[str, float | int]]
    by_tactic: dict[str, dict[str, float | int]]
    limitations: list[str]

    def to_dict(self):
        return asdict(self)


def _metrics(rows: list[EvaluationCase]) -> dict[str, float | int]:
    tp = sum(r.actual_scam and r.predicted_risk for r in rows)
    fp = sum((not r.actual_scam) and r.predicted_risk for r in rows)
    tn = sum((not r.actual_scam) and (not r.predicted_risk) for r in rows)
    fn = sum(r.actual_scam and (not r.predicted_risk) for r in rows)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    return {"samples": len(rows), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(precision, 4), "recall": round(recall, 4),
            "specificity": round(specificity, 4), "false_positive_rate": round(1 - specificity, 4),
            "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0}


def evaluate(cases: Iterable[EvaluationCase]) -> EvaluationReport:
    rows = list(cases)
    if not rows:
        raise ValueError("at least one evaluation case is required")
    by_language: dict[str, list[EvaluationCase]] = defaultdict(list)
    by_tactic: dict[str, list[EvaluationCase]] = defaultdict(list)
    for r in rows:
        by_language[r.language].append(r)
        by_tactic[r.tactic].append(r)
    m = _metrics(rows)
    return EvaluationReport(
        samples=len(rows), campaigns=len({r.campaign_id for r in rows}),
        true_positive=m["tp"], false_positive=m["fp"], true_negative=m["tn"], false_negative=m["fn"],
        precision=m["precision"], recall=m["recall"], specificity=m["specificity"],
        false_positive_rate=m["false_positive_rate"], f1=m["f1"],
        by_language={k: _metrics(v) for k, v in sorted(by_language.items())},
        by_tactic={k: _metrics(v) for k, v in sorted(by_tactic.items())},
        limitations=[
            "Metrics describe only the labelled evaluation set and are not population-wide guarantees.",
            "Evaluation data should be split by campaign and time, not randomly by near-duplicate message.",
            "Small language or tactic groups can have unstable metrics; display sample counts.",
        ],
    )


def split_by_campaign(cases: Iterable[EvaluationCase], *, test_fraction: float = 0.2,
                      salt: str = "toroka-phase4-v1") -> tuple[list[EvaluationCase], list[EvaluationCase]]:
    """Stable campaign-level split prevents near-identical campaign messages leaking across sets."""
    if not 0.05 <= test_fraction <= 0.5:
        raise ValueError("test_fraction must be between 0.05 and 0.5")
    train, test = [], []
    threshold = int(test_fraction * 10_000)
    for case in cases:
        bucket = int(hashlib.sha256(f"{salt}:{case.campaign_id}".encode()).hexdigest()[:8], 16) % 10_000
        (test if bucket < threshold else train).append(case)
    return train, test


def model_release_gate(report: EvaluationReport, *, min_samples: int = 200,
                       min_campaigns: int = 30, min_precision: float = 0.95,
                       min_recall: float = 0.80, max_false_positive_rate: float = 0.03) -> dict:
    checks = {
        "minimum_samples": report.samples >= min_samples,
        "minimum_campaigns": report.campaigns >= min_campaigns,
        "minimum_precision": report.precision is not None and report.precision >= min_precision,
        "minimum_recall": report.recall is not None and report.recall >= min_recall,
        "maximum_false_positive_rate": report.false_positive_rate is not None and report.false_positive_rate <= max_false_positive_rate,
    }
    return {"eligible_for_shadow_evaluation": all(checks.values()), "checks": checks,
            "note": "Passing this gate permits shadow evaluation only, not automatic production promotion or autonomous adverse decisions."}
