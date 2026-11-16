from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class IncidentSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentCategory(StrEnum):
    AI_QUALITY_FAILURE = "ai_quality_failure"
    DATA_QUALITY_FAILURE = "data_quality_failure"
    DETECTOR_FAILURE = "detector_failure"
    MODEL_DRIFT = "model_drift"
    SECURITY_EVENT = "security_event"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    EVIDENCE_INTEGRITY_FAILURE = "evidence_integrity_failure"
    INTEGRATION_FAILURE = "integration_failure"
    PROVIDER_OUTAGE = "provider_outage"
    INFRASTRUCTURE_FAILURE = "infrastructure_failure"
    AUDIT_FAILURE = "audit_failure"


class IncidentStatus(StrEnum):
    DETECTED = "detected"
    TRIAGED = "triaged"
    CONTAINED = "contained"
    INVESTIGATING = "investigating"
    REMEDIATED = "remediated"
    RECOVERED = "recovered"
    CLOSED = "closed"


@dataclass(frozen=True)
class GovernanceIncident:
    incident_id: str
    installation_id: str
    title: str
    category: IncidentCategory
    severity: IncidentSeverity
    status: IncidentStatus
    affected_components: tuple[str, ...]
    affected_case_ids: tuple[str, ...] = ()
    detection_source: str = "monitoring_system"
    detected_at: datetime | None = None
    contained_at: datetime | None = None
    resolved_at: datetime | None = None
    owner: str = "security_operations"
    remediation_notes: str | None = None
    post_incident_review: str | None = None


def correlate_incident_to_cases(
    affected_components: set[str],
    case_component_manifests: dict[str, set[str]],
) -> list[str]:
    """Identifies all investigation cases that executed or relied on the affected components."""
    impacted: list[str] = []
    for case_id, comps in case_component_manifests.items():
        if not affected_components.isdisjoint(comps):
            impacted.append(case_id)
    return sorted(impacted)
