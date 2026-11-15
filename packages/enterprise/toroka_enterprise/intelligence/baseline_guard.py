"""Baseline poisoning protection and auditable admission policies."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BaselineAdmissionDecision:
    accepted: bool
    reason: str


def should_enter_baseline(
    *,
    event_is_verified: bool,
    event_is_under_investigation: bool,
    event_is_correction: bool,
    event_is_test_data: bool,
    event_is_compromised: bool = False,
) -> BaselineAdmissionDecision:
    if not event_is_verified:
        return BaselineAdmissionDecision(
            accepted=False,
            reason="event_not_verified",
        )

    if event_is_under_investigation:
        return BaselineAdmissionDecision(
            accepted=False,
            reason="event_under_investigation",
        )

    if event_is_correction:
        return BaselineAdmissionDecision(
            accepted=False,
            reason="correction_event",
        )

    if event_is_test_data:
        return BaselineAdmissionDecision(
            accepted=False,
            reason="test_data",
        )

    if event_is_compromised:
        return BaselineAdmissionDecision(
            accepted=False,
            reason="compromised_event",
        )

    return BaselineAdmissionDecision(
        accepted=True,
        reason="eligible",
    )
