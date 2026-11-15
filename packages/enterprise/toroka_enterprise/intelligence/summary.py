from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .investigation import InvestigationBundle


@dataclass(frozen=True)
class InvestigationSummary:
    finding: str
    confidence: float

    supporting_facts: tuple[str, ...]
    alternative_explanations: tuple[str, ...]
    missing_evidence: tuple[str, ...]

    requires_human_review: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding": self.finding,
            "confidence": self.confidence,
            "supporting_facts": list(self.supporting_facts),
            "alternative_explanations": list(self.alternative_explanations),
            "missing_evidence": list(self.missing_evidence),
            "requires_human_review": self.requires_human_review,
        }


def summarize(
    investigation: InvestigationBundle,
) -> InvestigationSummary:
    signals = investigation.signals

    if not signals:
        return InvestigationSummary(
            finding="No correlated risk signal identified across available source feeds.",
            confidence=0.0,
            supporting_facts=(),
            alternative_explanations=(),
            missing_evidence=(
                "Additional source-system feeds or wider temporal windows may be required.",
            ),
            requires_human_review=False,
        )

    strongest = max(
        signals,
        key=lambda signal: signal.confidence,
    )

    facts = tuple(dict.fromkeys(signal.title for signal in signals))

    alternatives = tuple(
        dict.fromkeys(
            explanation
            for signal in signals
            for explanation in signal.alternative_explanations
        )
    )

    missing = tuple(
        dict.fromkeys(
            evidence
            for signal in signals
            for evidence in signal.missing_evidence
        )
    )

    return InvestigationSummary(
        finding=strongest.title,
        confidence=strongest.confidence,
        supporting_facts=facts,
        alternative_explanations=alternatives,
        missing_evidence=missing,
        requires_human_review=True,
    )
