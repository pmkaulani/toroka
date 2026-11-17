from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any
from .incidents import IncidentSeverity


class DriftType(StrEnum):
    DATA = "data"
    BEHAVIOUR = "behaviour"
    DETECTOR_VOLUME = "detector_volume"
    MODEL_OUTPUT = "model_output"
    AI_QUALITY = "ai_quality"
    INFRASTRUCTURE = "infrastructure"


class HealthStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class DriftRecord:
    drift_id: str
    drift_type: DriftType
    component_id: str
    metric_name: str
    baseline_value: float
    observed_value: float
    threshold: float
    severity: IncidentSeverity
    recommended_response: str
    detected_at: datetime
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SystemHealthOverview:
    overall_status: HealthStatus
    detection_health: HealthStatus
    data_quality_health: HealthStatus
    network_health: HealthStatus
    copilot_health: HealthStatus
    audit_integrity_health: HealthStatus
    active_drift_count: int
    open_incidents_count: int
    summary_message: str


def evaluate_metric_drift(
    drift_id: str,
    component_id: str,
    drift_type: DriftType,
    metric_name: str,
    baseline: float,
    observed: float,
    threshold: float,
    *,
    now: datetime,
    recommended_response: str = "",
) -> DriftRecord | None:
    """Detects if observed metric deviates from baseline beyond threshold ratio."""
    if baseline == 0.0:
        rel_diff = abs(observed)
    else:
        rel_diff = abs(observed - baseline) / abs(baseline)

    if rel_diff > threshold:
        # Determine severity
        if rel_diff >= threshold * 3.0:
            sev = IncidentSeverity.CRITICAL
        elif rel_diff >= threshold * 2.0:
            sev = IncidentSeverity.HIGH
        else:
            sev = IncidentSeverity.MEDIUM

        resp = recommended_response or (
            f"Observed {metric_name} deviated by {rel_diff*100:.1f}% (threshold {threshold*100:.1f}%). "
            f"Review recent component release or trigger model recalibration."
        )

        return DriftRecord(
            drift_id=drift_id,
            drift_type=drift_type,
            component_id=component_id,
            metric_name=metric_name,
            baseline_value=baseline,
            observed_value=observed,
            threshold=threshold,
            severity=sev,
            recommended_response=resp,
            detected_at=now,
        )
    return None
