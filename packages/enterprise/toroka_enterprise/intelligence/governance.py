"""Model and detector governance metadata and status tracking."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ModelStatus(StrEnum):
    DETERMINISTIC = "deterministic"
    EXPERIMENTAL = "experimental"
    VALIDATED = "validated"
    RETIRED = "retired"


@dataclass(frozen=True)
class DetectionMethod:
    method_id: str
    version: str

    status: ModelStatus

    description: str

    training_data: str | None = None
    validation_reference: str | None = None

    approved_by: str | None = None

    limitations: tuple[str, ...] = ()
