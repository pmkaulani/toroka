from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class HypothesisStatus(StrEnum):
    OPEN = "open"
    SUPPORTED = "supported"
    WEAKENED = "weakened"
    DISPROVEN = "disproven"


@dataclass(frozen=True)
class InvestigationHypothesis:
    hypothesis_id: str

    title: str
    description: str

    status: HypothesisStatus

    supporting_signal_ids: tuple[str, ...] = ()
    contradicting_signal_ids: tuple[str, ...] = ()

    confidence: float = 0.0

    investigator_note: str | None = None

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "title": self.title,
            "description": self.description,
            "status": self.status.value,
            "supporting_signal_ids": list(self.supporting_signal_ids),
            "contradicting_signal_ids": list(self.contradicting_signal_ids),
            "confidence": self.confidence,
            "investigator_note": self.investigator_note,
        }
