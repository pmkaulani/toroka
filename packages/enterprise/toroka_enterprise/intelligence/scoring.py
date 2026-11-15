"""Severity calculation for behavioral deviations based on maturity and deviation magnitude."""
from __future__ import annotations

from .anomalies import AnomalySeverity


def severity_from_deviation(
    deviation: float,
    *,
    mature: bool,
) -> AnomalySeverity:
    if not mature:
        return AnomalySeverity.LOW

    absolute = abs(deviation)

    if absolute >= 6:
        return AnomalySeverity.HIGH

    if absolute >= 4:
        return AnomalySeverity.MEDIUM

    return AnomalySeverity.LOW
