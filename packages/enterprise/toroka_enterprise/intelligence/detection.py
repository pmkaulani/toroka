"""Standard detector interface preserving evidence, provenance, and explanation."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class DetectionContext:
    installation_id: str
    subject_id: str


@dataclass(frozen=True)
class DetectionResult:
    detector_id: str
    detector_version: str

    signals: tuple[object, ...]

    evidence_ids: tuple[str, ...]

    explanation: str

    limitations: tuple[str, ...]


class Detector(Protocol):
    detector_id: str
    detector_version: str

    def detect(
        self,
        context: DetectionContext,
    ) -> DetectionResult:
        ...
