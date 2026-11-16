from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class GateStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"


MANDATORY_GATES = (
    "SECURITY",
    "DATA_CONTRACT",
    "MIGRATIONS",
    "AUDIT",
    "DETECTOR_VALIDATION",
    "AI_EVALUATION",
    "DR_TEST",
    "BACKUP_RESTORE",
    "MONITORING",
    "ACCESS_CONTROL",
    "INCIDENT_RESPONSE",
    "DOCUMENTATION",
    "APPROVAL",
)


@dataclass(frozen=True)
class ReadinessGate:
    gate_name: str
    status: GateStatus
    verified_by: str
    rationale: str
    evidence_reference: str | None = None


@dataclass(frozen=True)
class ReadinessAssessment:
    installation_id: str
    release_version: str
    overall_status: GateStatus
    gates: tuple[ReadinessGate, ...]
    evaluated_at: str

    @property
    def is_production_ready(self) -> bool:
        return self.overall_status == GateStatus.PASS


def evaluate_production_readiness(
    installation_id: str,
    release_version: str,
    gates_input: list[ReadinessGate],
    evaluated_at: str,
) -> ReadinessAssessment:
    """Evaluates all 13 bank readiness gates. Any failing mandatory gate blocks production readiness."""
    gate_dict = {g.gate_name: g for g in gates_input}

    # Ensure all mandatory gates are present
    evaluated_gates: list[ReadinessGate] = []
    has_fail = False

    for name in MANDATORY_GATES:
        if name in gate_dict:
            g = gate_dict[name]
            evaluated_gates.append(g)
            if g.status == GateStatus.FAIL:
                has_fail = True
        else:
            # Missing gate is an automatic failure
            evaluated_gates.append(
                ReadinessGate(
                    gate_name=name,
                    status=GateStatus.FAIL,
                    verified_by="automated_readiness_evaluator",
                    rationale=f"Mandatory readiness gate '{name}' has not been evaluated",
                )
            )
            has_fail = True

    overall = GateStatus.FAIL if has_fail else GateStatus.PASS
    return ReadinessAssessment(
        installation_id=installation_id,
        release_version=release_version,
        overall_status=overall,
        gates=tuple(evaluated_gates),
        evaluated_at=evaluated_at,
    )
