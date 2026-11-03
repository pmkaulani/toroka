from __future__ import annotations

from dataclasses import dataclass, asdict
from collections import defaultdict
from datetime import datetime
from typing import Iterable

ACTUAL_LABELS = {"scam", "legitimate", "inconclusive"}
PREDICTED_LABELS = {"scam", "suspicious", "legitimate", "inconclusive"}


@dataclass(frozen=True, slots=True)
class LabelledCase:
    case_ref: str
    campaign_ref: str
    observed_at: str
    actual_label: str
    predicted_label: str
    language: str = "undetermined"
    tactic: str = "other"

    def __post_init__(self):
        if self.actual_label not in ACTUAL_LABELS or self.predicted_label not in PREDICTED_LABELS:
            raise ValueError("actual labels must be scam/legitimate/inconclusive; predicted labels may also be suspicious")
        datetime.fromisoformat(self.observed_at.replace("Z", "+00:00"))
        if not self.case_ref or not self.campaign_ref:
            raise ValueError("case_ref and campaign_ref are required")


def _metrics(rows: list[LabelledCase]) -> dict:
    # Inconclusive predictions count as not flagged for positive-class metrics.
    predicted_positive = lambda r: r.predicted_label in {"scam", "suspicious"}
    tp = sum(r.actual_label == "scam" and predicted_positive(r) for r in rows)
    fp = sum(r.actual_label == "legitimate" and predicted_positive(r) for r in rows)
    tn = sum(r.actual_label == "legitimate" and not predicted_positive(r) for r in rows)
    fn = sum(r.actual_label == "scam" and not predicted_positive(r) for r in rows)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    fpr = fp / (fp + tn) if fp + tn else None
    f1 = 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else None
    return {"samples": len(rows), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": precision, "recall": recall, "false_positive_rate": fpr, "f1": f1}


def evaluate(cases: Iterable[LabelledCase]) -> dict:
    rows = list(cases)
    if not rows:
        raise ValueError("at least one evaluation case is required")
    if len({r.case_ref for r in rows}) != len(rows):
        raise ValueError("case_ref values must be unique")
    by_language: dict[str, list[LabelledCase]] = defaultdict(list)
    by_tactic: dict[str, list[LabelledCase]] = defaultdict(list)
    for row in rows:
        by_language[row.language].append(row)
        by_tactic[row.tactic].append(row)
    return {
        **_metrics(rows),
        "campaigns": len({r.campaign_ref for r in rows}),
        "by_language": {k: _metrics(v) for k, v in sorted(by_language.items())},
        "by_tactic": {k: _metrics(v) for k, v in sorted(by_tactic.items())},
        "limitations": [
            "Metrics describe the reviewed evaluation set, not all Toroka users or Kenyan scams.",
            "Campaign and time separation are required to prevent template leakage.",
            "Show sample counts beside every language/tactic metric; small groups are unstable.",
            "Inconclusive predictions count as not flagged in positive-class recall and false-negative calculations.",
        ],
    }


def temporal_campaign_split(cases: Iterable[LabelledCase], *, cutoff_iso: str) -> tuple[list[LabelledCase], list[LabelledCase]]:
    """Split by time, then reject campaigns that cross the cutoff to prevent leakage."""
    cutoff = datetime.fromisoformat(cutoff_iso.replace("Z", "+00:00"))
    rows = list(cases)
    train, test = [], []
    campaign_side: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        observed = datetime.fromisoformat(row.observed_at.replace("Z", "+00:00"))
        side = "test" if observed >= cutoff else "train"
        campaign_side[row.campaign_ref].add(side)
        (test if side == "test" else train).append(row)
    leaked = [campaign for campaign, sides in campaign_side.items() if len(sides) > 1]
    if leaked:
        raise ValueError("campaigns cross the temporal split; choose a later cutoff or group policy")
    return train, test


def release_gate(report: dict, *, min_samples: int = 300, min_campaigns: int = 40,
                 min_precision: float = 0.97, min_recall: float = 0.85,
                 max_false_positive_rate: float = 0.02, min_subgroup_samples: int = 40,
                 min_subgroup_recall: float = 0.75, max_subgroup_false_positive_rate: float = 0.05) -> dict:
    language_groups = report.get("by_language", {})
    checks = {
        "minimum_samples": report.get("samples", 0) >= min_samples,
        "minimum_campaigns": report.get("campaigns", 0) >= min_campaigns,
        "minimum_precision": report.get("precision") is not None and report["precision"] >= min_precision,
        "minimum_recall": report.get("recall") is not None and report["recall"] >= min_recall,
        "maximum_false_positive_rate": report.get("false_positive_rate") is not None and report["false_positive_rate"] <= max_false_positive_rate,
        "language_subgroups_have_minimum_samples": bool(language_groups) and all(v.get("samples", 0) >= min_subgroup_samples for v in language_groups.values()),
        "language_subgroup_recall_within_bound": bool(language_groups) and all(v.get("recall") is not None and v["recall"] >= min_subgroup_recall for v in language_groups.values()),
        "language_subgroup_false_positive_rate_within_bound": bool(language_groups) and all(v.get("false_positive_rate") is not None and v["false_positive_rate"] <= max_subgroup_false_positive_rate for v in language_groups.values()),
    }
    return {
        "eligible_for_shadow_canary": all(checks.values()),
        "checks": checks,
        "deployment_authorized": False,
        "note": "Passing permits a monitored shadow canary review only. A human release owner must approve any production change.",
    }
