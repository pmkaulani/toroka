from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .entities import Relationship
from .events import IntelligenceEvent
from .hypotheses import InvestigationHypothesis
from .signals import CorrelationSignal


@dataclass
class InvestigationBundle:
    investigation_id: str
    installation_id: str

    anchor_event_ids: list[str] = field(default_factory=list)

    events: list[IntelligenceEvent] = field(default_factory=list)

    relationships: list[Relationship] = field(default_factory=list)

    signals: list[CorrelationSignal] = field(default_factory=list)

    hypotheses: list[InvestigationHypothesis] = field(default_factory=list)

    missing_evidence: list[str] = field(default_factory=list)

    def add_event(self, event: IntelligenceEvent) -> None:
        if event.installation_id != self.installation_id:
            raise ValueError(
                f"installation mismatch: cannot add event from '{event.installation_id}' to bundle for '{self.installation_id}'"
            )
        if event not in self.events:
            self.events.append(event)

    def add_relationship(self, relationship: Relationship) -> None:
        if relationship.installation_id != self.installation_id:
            raise ValueError(
                f"installation mismatch: cannot add relationship from '{relationship.installation_id}' to bundle for '{self.installation_id}'"
            )
        if relationship not in self.relationships:
            self.relationships.append(relationship)

    def add_signal(self, signal: CorrelationSignal) -> None:
        if signal not in self.signals:
            self.signals.append(signal)

    def add_hypothesis(self, hypothesis: InvestigationHypothesis) -> None:
        # Replace if hypothesis_id already exists, otherwise append
        for idx, h in enumerate(self.hypotheses):
            if h.hypothesis_id == hypothesis.hypothesis_id:
                self.hypotheses[idx] = hypothesis
                return
        self.hypotheses.append(hypothesis)

    def to_dict(self) -> dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "installation_id": self.installation_id,
            "anchor_event_ids": list(self.anchor_event_ids),
            "events": [e.to_dict() for e in self.events],
            "relationships": [r.to_dict() for r in self.relationships],
            "signals": [s.to_dict() for s in self.signals],
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "missing_evidence": list(self.missing_evidence),
        }
