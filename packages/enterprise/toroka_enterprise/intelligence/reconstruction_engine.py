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
from .sources import DEFAULT_SOURCE_RELIABILITIES


def get_source_evidence_strength(source_system: str | None) -> float:
    """Returns the evidence strength weight calibrated to the source system reliability."""
    if not source_system:
        return 0.65
    key = source_system.lower().strip()
    if key == "switch":
        key = "payment_switch"
    rel = DEFAULT_SOURCE_RELIABILITIES.get(key)
    return rel.weight if rel else 0.70


def reconstruct(
    *,
    reconstruction_id: str,
    installation_id: str,
    title: str,
    events: list[IntelligenceEvent],
) -> AttackReconstruction:
    """Deterministically reconstructs an attack timeline from independently sourced canonical events."""
    # Deterministic chronological sort with event_id tie-breaker
    ordered = sorted(
        (
            event
            for event in events
            if event.installation_id == installation_id
        ),
        key=lambda event: (event.event_time, event.event_id),
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
        strength = get_source_evidence_strength(event.source_system)
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
                evidence_strength=strength,
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

    # Confidence reflects evidence strength, source diversity, and presence of contradictions
    distinct_sources = {e.source_system for e in ordered if e.source_system}
    avg_strength = (
        sum(s.evidence_strength for s in reconstruction.steps) / len(reconstruction.steps)
        if reconstruction.steps else 0.5
    )
    if len(distinct_sources) >= 2:
        base_confidence = min(0.92, round(avg_strength, 2))
    else:
        base_confidence = min(0.70, round(avg_strength * 0.8, 2))

    if contradictions:
        reconstruction.confidence = max(0.15, round(base_confidence - (len(contradictions) * 0.15), 2))
    else:
        reconstruction.confidence = base_confidence

    return reconstruction
