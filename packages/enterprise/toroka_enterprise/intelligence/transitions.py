"""State transition identification and sensitive operational shift detection."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .events import IntelligenceEvent


@dataclass(frozen=True)
class StateTransition:
    previous_state: str
    new_state: str
    event_id: str
    explanation: str
    material_change: bool


SENSITIVE_TRANSITIONS: set[tuple[str, str]] = {
    ("normal", "beneficiary_changed"),
    ("normal", "limit_changed"),
    ("normal", "account_restricted"),
    ("normal", "account_unrestricted"),
    ("normal", "high_value_transfer"),
    ("customer_profile", "contact_details_changed"),
    ("dormant", "active"),
    ("normal", "contact_details_changed"),
    ("normal", "password_reset"),
    ("normal", "mfa_disabled"),
}


def identify_transition(
    previous_state: str,
    new_state: str,
    event_id: str,
) -> StateTransition:
    material = (previous_state, new_state) in SENSITIVE_TRANSITIONS
    return StateTransition(
        previous_state=previous_state,
        new_state=new_state,
        event_id=event_id,
        explanation=f"State changed from {previous_state} to {new_state}",
        material_change=material,
    )


def extract_transitions_from_events(
    events: list[IntelligenceEvent],
) -> list[StateTransition]:
    """Infers state transitions sequentially across a set of chronological events."""
    transitions: list[StateTransition] = []
    
    # State tracking per subject
    current_states: dict[str, str] = {}

    for evt in events:
        subj = evt.subject or "global"
        prev = current_states.get(subj, "normal")
        new_st = prev

        etype = evt.event_type.lower()
        if "beneficiary" in etype and ("change" in etype or "add" in etype):
            new_st = "beneficiary_changed"
        elif "limit" in etype:
            new_st = "limit_changed"
        elif "contact" in etype or "profile" in etype:
            new_st = "contact_details_changed"
        elif "transfer" in etype or "payout" in etype or "payment" in etype:
            amt = evt.attributes.get("amount", 0.0) if hasattr(evt, "attributes") and evt.attributes else 0.0
            if amt and float(amt) >= 500000.0:
                new_st = "high_value_transfer"
        elif "dormant" in etype:
            new_st = "dormant"
        elif "activate" in etype:
            new_st = "active"

        if new_st != prev:
            t = identify_transition(prev, new_st, evt.event_id)
            transitions.append(t)
            current_states[subj] = new_st

    return transitions
