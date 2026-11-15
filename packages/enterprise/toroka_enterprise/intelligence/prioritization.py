"""Investigation prioritization based on explainable components.

IMPORTANT INSTITUTIONAL BANKING DISTINCTION:
The priority score produced by this module is an operational TRIAGE PRIORITY metric
designed to assist human investigators in ordering work queues. It is explicitly
NOT a probability of fraud, nor is it an accusation or evaluation of individual guilt.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .anomalies import BehavioralAnomaly
from .signals import CorrelationSignal
from .sources import get_source_reliability


@dataclass(frozen=True)
class InvestigationPriority:
    priority_score: float
    reasons: tuple[str, ...]
    requires_review: bool
    independent_sources_count: int = 1
    unresolved_contradictions: int = 0


def calculate_priority(
    *,
    signals: list[CorrelationSignal],
    anomalies: list[BehavioralAnomaly],
    unresolved_contradictions: int = 0,
    distinct_sources: set[str] | None = None,
) -> InvestigationPriority:
    score = 0.0
    reasons: list[str] = []

    # Track independent source systems to reward multi-source corroboration
    extracted_sources: set[str] = set()
    if distinct_sources:
        extracted_sources.update(s.lower().strip() for s in distinct_sources if s)

    for signal in signals:
        # Extract sources from signal evidence if present
        for ev in signal.evidence:
            if isinstance(ev, dict):
                src = ev.get("source_system") or ev.get("source")
                if src and isinstance(src, str):
                    extracted_sources.add(src.lower().strip())

        # Base severity score
        sev = signal.severity.value if hasattr(signal.severity, "value") else str(signal.severity)
        if sev == "critical":
            score += 40.0
        elif sev == "high":
            score += 25.0
        elif sev == "medium":
            score += 15.0
        else:
            score += 5.0

        # Confidence contribution (up to 10 points per signal)
        score += signal.confidence * 10.0

        reasons.append(f"Correlation signal: {signal.title}")

    # Reward independent cross-system corroboration
    source_count = max(len(extracted_sources), 1)
    if source_count > 1:
        corroboration_bonus = min((source_count - 1) * 5.0, 15.0)
        score += corroboration_bonus
        source_names = ", ".join(sorted(extracted_sources))
        reasons.append(
            f"Corroborated across {source_count} independent sources ({source_names})"
        )

    # Behavioral anomalies contribution
    for anomaly in anomalies:
        sev = anomaly.severity.value if hasattr(anomaly.severity, "value") else str(anomaly.severity)
        if sev == "high":
            score += 20.0
        elif sev == "medium":
            score += 10.0
        else:
            score += 3.0

        if anomaly.baseline_mature:
            reasons.append(
                f"Established behavioral deviation: {anomaly.dimension}"
            )
        else:
            reasons.append(
                f"Limited-history behavioral deviation: {anomaly.dimension}"
            )

    # Note any unresolved contradictions
    if unresolved_contradictions > 0:
        reasons.append(
            f"Note: {unresolved_contradictions} competing explanation(s) or contradiction(s) require review"
        )

    score = min(score, 100.0)

    return InvestigationPriority(
        priority_score=round(score, 2),
        reasons=tuple(reasons),
        requires_review=score >= 40.0,
        independent_sources_count=source_count,
        unresolved_contradictions=unresolved_contradictions,
    )
