"""Behavioral anomaly structures preserving explainability and provenance."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class AnomalySeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class BehavioralAnomaly:
    anomaly_id: str
    installation_id: str
    subject_id: str

    dimension: str

    observed_value: float
    expected_value: float

    deviation: float

    severity: AnomalySeverity

    confidence: float

    explanation: str

    baseline_sample_count: int

    baseline_mature: bool

    limitations: tuple[str, ...] = ()
    provenance: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0 <= self.confidence <= 1:
            raise ValueError(
                "confidence must be between 0 and 1"
            )
