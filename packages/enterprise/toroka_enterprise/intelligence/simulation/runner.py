from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from ..events import IntelligenceEvent
from ..rules import (
    authentication_anomaly_with_sensitive_action,
    customer_complaint_correlated_employee_activity,
    employee_access_before_sensitive_change,
    employee_activity_before_reversal_or_closure,
    privileged_login_before_unusual_transaction,
    role_change_before_sensitive_activity,
)
from ..signals import CorrelationSignal
from .domain import CandidateDetection, SEVERITY_ORDER, SimulationStrategy

RuleFunction = Callable[[list[IntelligenceEvent]], list[CorrelationSignal]]

RULE_REGISTRY: dict[str, RuleFunction] = {
    "employee_access_before_sensitive_change": employee_access_before_sensitive_change,
    "privileged_login_before_unusual_transaction": privileged_login_before_unusual_transaction,
    "role_change_before_sensitive_activity": role_change_before_sensitive_activity,
    "employee_activity_before_reversal_or_closure": employee_activity_before_reversal_or_closure,
    "customer_complaint_correlated_employee_activity": customer_complaint_correlated_employee_activity,
    "authentication_anomaly_with_sensitive_action": authentication_anomaly_with_sensitive_action,
}

# Aliases for flexibility
RULE_ALIASES: dict[str, str] = {
    "access_before_sensitive_change": "employee_access_before_sensitive_change",
    "privileged_login": "privileged_login_before_unusual_transaction",
    "role_change": "role_change_before_sensitive_activity",
    "reversal_or_closure": "employee_activity_before_reversal_or_closure",
    "customer_complaint": "customer_complaint_correlated_employee_activity",
    "auth_anomaly": "authentication_anomaly_with_sensitive_action",
}


def resolve_rule_name(name: str) -> str:
    """Normalize rule identifier to registry key."""
    if name in RULE_REGISTRY:
        return name
    if name in RULE_ALIASES:
        return RULE_ALIASES[name]
    return name


def run_strategy_detectors(
    strategy: SimulationStrategy,
    case_id: str,
    events: list[IntelligenceEvent],
) -> list[CandidateDetection]:
    """Execute strategy rules against a sequence of replayed case events.

    Filters candidate detections by the strategy's minimum severity and confidence thresholds.
    """
    if not events:
        return []

    # Map event ID to event for fast timestamp lookup
    event_lookup: dict[str, IntelligenceEvent] = {e.event_id: e for e in events}
    min_sev_score = SEVERITY_ORDER.get(strategy.min_severity.lower(), 2)

    detections: list[CandidateDetection] = []

    for raw_rule_name in strategy.rules_enabled:
        canonical_name = resolve_rule_name(raw_rule_name)
        rule_fn = RULE_REGISTRY.get(canonical_name)
        if not rule_fn:
            continue

        try:
            signals = rule_fn(events)
        except Exception:
            # Detectors in simulation must never crash the replay loop
            continue

        for sig in signals:
            sig_sev_str = sig.severity.value if hasattr(sig.severity, "value") else str(sig.severity)
            sig_sev_score = SEVERITY_ORDER.get(sig_sev_str.lower(), 0)

            # Filter by severity and confidence
            if sig_sev_score < min_sev_score:
                continue
            if sig.confidence < strategy.min_confidence:
                continue

            # Determine detected_at: timestamp of the latest event in the signal trigger
            sig_times: list[datetime] = []
            for ev_id in sig.event_ids:
                if ev_id in event_lookup:
                    sig_times.append(event_lookup[ev_id].event_time)

            if sig_times:
                detected_at = max(sig_times)
            else:
                detected_at = events[-1].event_time

            primary_event_id = sig.event_ids[-1] if sig.event_ids else events[-1].event_id

            detection = CandidateDetection(
                detection_id=f"sim_{strategy.strategy_id}_v{strategy.version}_{sig.signal_id}",
                case_id=case_id,
                event_id=primary_event_id,
                detected_at=detected_at,
                rule_name=canonical_name,
                severity=sig_sev_str,
                confidence=sig.confidence,
                explanation=sig.explanation,
                supporting_event_ids=tuple(sig.event_ids),
                metadata={
                    "strategy_id": strategy.strategy_id,
                    "strategy_version": strategy.version,
                    "title": sig.title,
                },
            )
            detections.append(detection)

    return detections


def make_rule_runner(
    strategy: SimulationStrategy,
) -> Callable[[str, list[IntelligenceEvent]], list[CandidateDetection]]:
    """Return a closure for running the strategy rules against case events."""
    return lambda case_id, events: run_strategy_detectors(strategy, case_id, events)
