"""The central Attack Reconstruction domain model."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class ReconstructionStep:
    sequence: int
    event_id: str
    event_type: str
    event_time: datetime
    actor_id: str | None
    subject_id: str | None
    source_system: str | None
    explanation: str
    evidence_strength: float
    provenance_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.sequence < 0:
            raise ValueError("sequence cannot be negative")
        if not 0.0 <= self.evidence_strength <= 1.0:
            raise ValueError("evidence_strength must be between 0 and 1")


@dataclass
class AttackReconstruction:
    reconstruction_id: str
    installation_id: str
    title: str
    start_time: datetime
    end_time: datetime
    steps: list[ReconstructionStep] = field(default_factory=list)
    entities: set[str] = field(default_factory=set)
    unresolved_questions: list[str] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)
    confidence: float = 0.0

    def add_step(
        self,
        step: ReconstructionStep,
    ) -> None:
        self.steps.append(step)
        if step.actor_id:
            self.entities.add(step.actor_id)
        if step.subject_id:
            self.entities.add(step.subject_id)

    def add_question(
        self,
        question: str,
    ) -> None:
        self.unresolved_questions.append(question)

    def add_contradiction(
        self,
        contradiction: str,
    ) -> None:
        self.contradictions.append(contradiction)
