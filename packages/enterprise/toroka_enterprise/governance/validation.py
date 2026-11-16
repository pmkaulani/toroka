from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class ValidationResult(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class ValidationMetric:
    name: str
    value: float
    threshold: float | None
    direction: str | None  # "gte", "lte", "eq"
    result: ValidationResult


@dataclass(frozen=True)
class ValidationRun:
    run_id: str
    component_id: str
    component_version: str
    dataset_digest: str
    configuration_digest: str
    metrics: tuple[ValidationMetric, ...]
    result: ValidationResult
    evaluator: str
    started_at: str
    completed_at: str
    limitations: tuple[str, ...] = ()

    def passed(self) -> bool:
        return self.result == ValidationResult.PASS


def evaluate_metric(
    name: str,
    value: float,
    threshold: float | None,
    direction: str | None = "gte",
) -> ValidationMetric:
    if threshold is None or direction is None:
        return ValidationMetric(
            name=name,
            value=value,
            threshold=threshold,
            direction=direction,
            result=ValidationResult.PASS,
        )

    res = ValidationResult.FAIL
    if direction == "gte" and value >= threshold:
        res = ValidationResult.PASS
    elif direction == "lte" and value <= threshold:
        res = ValidationResult.PASS
    elif direction == "eq" and abs(value - threshold) < 1e-6:
        res = ValidationResult.PASS

    return ValidationMetric(
        name=name,
        value=value,
        threshold=threshold,
        direction=direction,
        result=res,
    )


def validate_detector_metrics(
    tp: int,
    fp: int,
    tn: int,
    fn: int,
    *,
    min_precision: float = 0.80,
    min_recall: float = 0.70,
    max_fpr: float = 0.05,
    max_latency_ms: float = 100.0,
    observed_latency_ms: float = 25.0,
) -> list[ValidationMetric]:
    """Computes and evaluates standard detection performance metrics for deterministic detectors."""
    total_pos = tp + fn
    total_neg = tn + fp
    total_pred_pos = tp + fp

    precision = (tp / total_pred_pos) if total_pred_pos > 0 else 0.0
    recall = (tp / total_pos) if total_pos > 0 else 0.0
    fpr = (fp / total_neg) if total_neg > 0 else 0.0

    metrics = [
        evaluate_metric("precision", precision, min_precision, "gte"),
        evaluate_metric("recall", recall, min_recall, "gte"),
        evaluate_metric("false_positive_rate", fpr, max_fpr, "lte"),
        evaluate_metric("execution_latency_ms", observed_latency_ms, max_latency_ms, "lte"),
    ]
    return metrics


def calculate_validation_result(metrics: list[ValidationMetric]) -> ValidationResult:
    """Calculates overall run outcome; any failing metric fails the run."""
    if not metrics:
        return ValidationResult.INCONCLUSIVE
    if any(m.result == ValidationResult.FAIL for m in metrics):
        return ValidationResult.FAIL
    if any(m.result == ValidationResult.INCONCLUSIVE for m in metrics):
        return ValidationResult.INCONCLUSIVE
    return ValidationResult.PASS
