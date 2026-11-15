"""Robust statistical deviation calculations using Median Absolute Deviation (MAD)."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DeviationResult:
    value: float
    baseline_median: float
    median_absolute_deviation: float
    modified_z_score: float | None

    is_anomalous: bool


def median(values: list[float]) -> float:
    if not values:
        raise ValueError("values cannot be empty")

    sorted_vals = sorted(values)
    middle = len(sorted_vals) // 2

    if len(sorted_vals) % 2:
        return float(sorted_vals[middle])

    return float(
        sorted_vals[middle - 1]
        + sorted_vals[middle]
    ) / 2.0


def calculate_deviation(
    value: float,
    baseline: list[float],
    *,
    threshold: float = 3.5,
) -> DeviationResult:
    if not baseline:
        raise ValueError("baseline cannot be empty")

    baseline_median = median(baseline)

    absolute_deviations = [
        abs(item - baseline_median)
        for item in baseline
    ]

    mad = median(absolute_deviations)

    if mad == 0:
        modified_z = None
        anomalous = (value != baseline_median)
    else:
        modified_z = (
            0.6745
            * (value - baseline_median)
            / mad
        )
        anomalous = abs(modified_z) >= threshold

    return DeviationResult(
        value=float(value),
        baseline_median=float(baseline_median),
        median_absolute_deviation=float(mad),
        modified_z_score=round(modified_z, 4) if modified_z is not None else None,
        is_anomalous=anomalous,
    )
