"""Deterministic attack reconstruction engine generating chronological steps from evidence."""
from __future__ import annotations

from datetime import datetime
from .events import IntelligenceEvent
from .reconstruction import (
    AttackReconstruction,
    ReconstructionStep,
)
from .transitions import extract_transitions_from_events
from .contradictions import detect_evidence_contradictions


def reconstruct(
    *,
    reconstruction_id: str,
    installation_id: str,
    title: str,
    events: list[IntelligenceEvent],
) -> AttackReconstruction:
    """Deterministically reconstructs an attack timeline from independently sourced canonical events."""
    ordered = sorted(
        (
            event
            for event in events
            if event.installation_id == installation_id
        ),
        key=lambda event: event.event_time,
    )

    if not ordered:
        raise ValueError(
            "cannot reconstruct from empty event set"
        )

    reconstruction = AttackReconstruction(
        reconstruction_id=reconstruction_id,
        installation_id=installation_id,
        title=title,
        start_time=ordered[0].event_time,
        end_time=ordered[-1].event_time,
    )

    for index, event in enumerate(ordered):
        reconstruction.add_step(
            ReconstructionStep(
                sequence=index,
                event_id=event.event_id,
                event_type=event.event_type,
                event_time=event.event_time,
                actor_id=event.actor,
                subject_id=event.subject,
                source_system=event.source_system,
                explanation=(
                    f"{event.event_type} recorded by "
                    f"{event.source_system or 'unknown source'}"
                ),
                evidence_strength=1.0,
                provenance_ids=(
                    event.source_record_id,
                ) if event.source_record_id else (),
            )
        )

    # Detect state transitions and contradictions
    transitions = extract_transitions_from_events(ordered)
    for t in transitions:
        if t.material_change:
            reconstruction.add_question(
                f"What authorized the state transition '{t.previous_state}' -> '{t.new_state}' (Event {t.event_id})?"
            )

    contradictions = detect_evidence_contradictions(ordered)
    for c in contradictions:
        reconstruction.add_contradiction(
            f"Contradiction [{c.severity.upper()}]: {c.explanation}"
        )

    # Base confidence reflects absence of unresolved critical contradictions
    if contradictions:
        reconstruction.confidence = max(0.5, round(1.0 - (len(contradictions) * 0.1), 2))
    else:
        reconstruction.confidence = 1.0

    return reconstruction
