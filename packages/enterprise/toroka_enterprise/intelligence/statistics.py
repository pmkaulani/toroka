"""Deterministic baseline statistical calculations."""
from __future__ import annotations

from dataclasses import dataclass
import math


@dataclass(frozen=True)
class BaselineStatistics:
    count: int
    mean: float
    standard_deviation: float
    minimum: float
    maximum: float
    median: float | None = None


def calculate_statistics(
    values: list[float],
) -> BaselineStatistics:
    if not values:
        raise ValueError("cannot calculate baseline from empty values")

    ordered = sorted(values)

    mean = sum(values) / len(values)

    variance = (
        sum((value - mean) ** 2 for value in values)
        / len(values)
    )

    stddev = math.sqrt(variance)

    midpoint = len(ordered) // 2

    if len(ordered) % 2:
        median = float(ordered[midpoint])
    else:
        median = float(
            ordered[midpoint - 1]
            + ordered[midpoint]
        ) / 2.0

    return BaselineStatistics(
        count=len(values),
        mean=mean,
        standard_deviation=stddev,
        minimum=float(min(values)),
        maximum=float(max(values)),
        median=median,
    )
