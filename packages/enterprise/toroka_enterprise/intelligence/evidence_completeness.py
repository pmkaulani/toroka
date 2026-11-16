"""Evidence completeness and Evidence Debt calculation."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EvidenceRequirement:
    evidence_type: str
    required: bool = True


DEFAULT_INVESTIGATION_REQUIREMENTS: list[EvidenceRequirement] = [
    EvidenceRequirement(evidence_type="iam", required=True),
    EvidenceRequirement(evidence_type="core_banking", required=True),
    EvidenceRequirement(evidence_type="payment_switch", required=True),
    EvidenceRequirement(evidence_type="crm", required=True),
    EvidenceRequirement(evidence_type="siem", required=True),
    EvidenceRequirement(evidence_type="hr", required=False),
]


@dataclass(frozen=True)
class EvidenceCompleteness:
    total_requirements: int
    satisfied_requirements: int
    missing_requirements: tuple[str, ...]

    @property
    def percentage(self) -> float:
        if self.total_requirements == 0:
            return 100.0
        return round(
            (self.satisfied_requirements / self.total_requirements) * 100,
            2,
        )

    @property
    def evidence_debt(self) -> tuple[str, ...]:
        """Missing required evidence components representing institutional Evidence Debt."""
        return self.missing_requirements


def calculate_evidence_completeness(
    available_sources: set[str],
    requirements: list[EvidenceRequirement] | None = None,
) -> EvidenceCompleteness:
    """Calculates evidence completeness and identifies institutional Evidence Debt."""
    reqs = requirements if requirements is not None else DEFAULT_INVESTIGATION_REQUIREMENTS
    required_only = [r for r in reqs if r.required]

    norm_available = {s.lower().strip() for s in available_sources if s}
    satisfied = 0
    missing: list[str] = []

    for r in required_only:
        if r.evidence_type.lower().strip() in norm_available:
            satisfied += 1
        else:
            missing.append(r.evidence_type)

    return EvidenceCompleteness(
        total_requirements=len(required_only),
        satisfied_requirements=satisfied,
        missing_requirements=tuple(missing),
    )
