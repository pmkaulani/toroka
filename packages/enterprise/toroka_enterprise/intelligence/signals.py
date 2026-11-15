from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class SignalSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class CorrelationSignal:
    """A cross-system correlation signal.

    IMPORTANT INSTITUTIONAL BANKING DISTINCTION:
    Confidence represents the statistical or deterministic confidence that the
    OBSERVED TEMPORAL OR CROSS-SYSTEM PATTERN genuinely occurred as recorded.
    It does NOT represent a probability or accusation that an individual employee
    or customer committed fraud or misconduct.
    """
    signal_id: str
    signal_type: str
    severity: SignalSeverity

    title: str
    explanation: str

    event_ids: tuple[str, ...]

    confidence: float

    evidence: tuple[dict[str, Any], ...] = ()

    alternative_explanations: tuple[str, ...] = ()

    missing_evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "signal_type": self.signal_type,
            "severity": self.severity.value,
            "title": self.title,
            "explanation": self.explanation,
            "event_ids": list(self.event_ids),
            "confidence": self.confidence,
            "evidence": [dict(e) for e in self.evidence],
            "alternative_explanations": list(self.alternative_explanations),
            "missing_evidence": list(self.missing_evidence),
        }
