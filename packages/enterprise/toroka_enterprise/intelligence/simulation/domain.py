from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
import uuid

from ..events import IntelligenceEvent


class OutcomeLabel(StrEnum):
    CONFIRMED_FRAUD = "confirmed_fraud"
    CONFIRMED_LEGITIMATE = "confirmed_legitimate"
    INCONCLUSIVE = "inconclusive"
    UNLABELLED = "unlabelled"


SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(frozen=True)
class SimulationStrategy:
    """Immutable definition of a counterfactual detection strategy."""

    strategy_id: str
    version: int
    title: str
    description: str
    rules_enabled: tuple[str, ...]
    parameters: dict[str, Any] = field(default_factory=dict)
    min_severity: str = "medium"
    min_confidence: float = 0.5
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = "system"
    status: str = "draft"  # draft, pending_review, approved, rejected, active

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy_id": self.strategy_id,
            "version": self.version,
            "title": self.title,
            "description": self.description,
            "rules_enabled": list(self.rules_enabled),
            "parameters": dict(self.parameters),
            "min_severity": self.min_severity,
            "min_confidence": self.min_confidence,
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SimulationStrategy:
        created_at = data.get("created_at")
        if isinstance(created_at, str):
            dt = datetime.fromisoformat(created_at)
        elif isinstance(created_at, datetime):
            dt = created_at
        else:
            dt = datetime.now(timezone.utc)

        return cls(
            strategy_id=data["strategy_id"],
            version=int(data.get("version", 1)),
            title=data.get("title", ""),
            description=data.get("description", ""),
            rules_enabled=tuple(data.get("rules_enabled", ())),
            parameters=dict(data.get("parameters", {})),
            min_severity=data.get("min_severity", "medium"),
            min_confidence=float(data.get("min_confidence", 0.5)),
            created_at=dt,
            created_by=data.get("created_by", "system"),
            status=data.get("status", "draft"),
        )


@dataclass(frozen=True)
class ReplayObservation:
    """An event presented to the replay engine.

    Includes both `event_time` (when the underlying action occurred)
    and `available_at` (when the telemetry was ingested and available to the bank).
    In counterfactual replay, an event is only visible at time T if available_at <= T.
    """

    event_id: str
    event_time: datetime
    available_at: datetime
    source_system: str
    event_type: str
    actor_id: str | None = None
    subject_id: str | None = None
    case_id: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    entities: tuple[str, ...] = ()

    def to_intelligence_event(self, installation_id: str) -> IntelligenceEvent:
        attrs = dict(self.payload)
        attrs["available_at"] = self.available_at.isoformat()
        if self.case_id:
            attrs["case_id"] = self.case_id

        return IntelligenceEvent(
            installation_id=installation_id,
            event_id=self.event_id,
            event_type=self.event_type,
            event_time=self.event_time,
            actor=self.actor_id,
            subject=self.subject_id,
            source_system=self.source_system,
            source_record_id=self.event_id,
            entities=self.entities,
            attributes=attrs,
        )

    @classmethod
    def from_intelligence_event(
        cls,
        event: IntelligenceEvent,
        available_at: datetime | None = None,
        case_id: str | None = None,
    ) -> ReplayObservation:
        eff_avail = available_at
        if eff_avail is None:
            raw_avail = event.attributes.get("available_at")
            if isinstance(raw_avail, str):
                try:
                    eff_avail = datetime.fromisoformat(raw_avail)
                except Exception:
                    eff_avail = event.event_time
            elif isinstance(raw_avail, datetime):
                eff_avail = raw_avail
            else:
                eff_avail = event.event_time

        c_id = case_id or event.attributes.get("case_id")
        return cls(
            event_id=event.event_id,
            event_time=event.event_time,
            available_at=eff_avail,
            source_system=event.source_system or "unknown",
            event_type=event.event_type,
            actor_id=event.actor,
            subject_id=event.subject,
            case_id=c_id,
            payload=dict(event.attributes),
            entities=tuple(event.entities),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_time": self.event_time.isoformat(),
            "available_at": self.available_at.isoformat(),
            "source_system": self.source_system,
            "event_type": self.event_type,
            "actor_id": self.actor_id,
            "subject_id": self.subject_id,
            "case_id": self.case_id,
            "payload": dict(self.payload),
            "entities": list(self.entities),
        }


@dataclass(frozen=True)
class CandidateDetection:
    """A simulated detection emitted by a strategy rule during replay."""

    detection_id: str
    case_id: str
    event_id: str
    detected_at: datetime
    rule_name: str
    severity: str
    confidence: float
    explanation: str
    supporting_event_ids: tuple[str, ...]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "case_id": self.case_id,
            "event_id": self.event_id,
            "detected_at": self.detected_at.isoformat(),
            "rule_name": self.rule_name,
            "severity": self.severity,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "supporting_event_ids": list(self.supporting_event_ids),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class SimulatedDetection:
    """Enriched detection record with strategy provenance."""

    detection_id: str
    strategy_id: str
    strategy_version: int
    case_id: str
    event_id: str
    detected_at: datetime
    rule_name: str
    severity: str
    confidence: float
    explanation: str
    supporting_event_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "strategy_id": self.strategy_id,
            "strategy_version": self.strategy_version,
            "case_id": self.case_id,
            "event_id": self.event_id,
            "detected_at": self.detected_at.isoformat(),
            "rule_name": self.rule_name,
            "severity": self.severity,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "supporting_event_ids": list(self.supporting_event_ids),
        }
