from __future__ import annotations

from dataclasses import dataclass, asdict
import math


@dataclass(slots=True)
class DriftReport:
    status: str
    psi: float | None
    threshold: float
    baseline_samples: int
    current_samples: int
    alert: bool
    limitations: list[str]

    def to_dict(self):
        return asdict(self)


def population_stability_index(baseline: dict[str, int], current: dict[str, int], *, epsilon: float = 1e-6) -> float:
    if not baseline or not current:
        raise ValueError("baseline and current distributions are required")
    if any(not isinstance(v, int) or v < 0 for v in list(baseline.values()) + list(current.values())):
        raise ValueError("distribution counts must be non-negative integers")
    base_n, curr_n = sum(baseline.values()), sum(current.values())
    if base_n == 0 or curr_n == 0:
        raise ValueError("distribution totals must be greater than zero")
    keys = set(baseline) | set(current)
    psi = 0.0
    for key in keys:
        p = max(baseline.get(key, 0) / base_n, epsilon)
        q = max(current.get(key, 0) / curr_n, epsilon)
        psi += (q - p) * math.log(q / p)
    return round(psi, 6)


def assess_drift(baseline: dict[str, int], current: dict[str, int], *, threshold: float = 0.2,
                 min_samples: int = 50) -> DriftReport:
    if not math.isfinite(threshold) or threshold <= 0:
        raise ValueError("threshold must be a finite positive number")
    if min_samples < 2:
        raise ValueError("min_samples must be at least 2")
    base_n, curr_n = sum(baseline.values()), sum(current.values())
    if base_n < min_samples or curr_n < min_samples:
        return DriftReport("insufficient_samples", None, threshold, base_n, curr_n, False,
                           ["Small windows are not sufficient for a stable drift estimate."])
    psi = population_stability_index(baseline, current)
    return DriftReport("drift_alert" if psi >= threshold else "within_threshold", psi, threshold,
                       base_n, curr_n, psi >= threshold,
                       ["Drift is a monitoring signal, not proof of model failure.",
                        "Do not automatically retrain or change verdict thresholds from this report."])
