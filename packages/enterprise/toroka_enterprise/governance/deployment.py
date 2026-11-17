from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from .readiness import ReadinessAssessment, MANDATORY_GATES, GateStatus


class DeploymentEnvironment(StrEnum):
    DEVELOPMENT = "development"
    VALIDATION = "validation"
    PILOT = "pilot"
    PRODUCTION = "production"


class ReleaseStatus(StrEnum):
    DRAFT = "draft"
    VALIDATED = "validated"
    APPROVED = "approved"
    STAGED = "staged"
    ACTIVE = "active"
    ROLLED_BACK = "rolled_back"
    RETIRED = "retired"


@dataclass(frozen=True)
class ProductionReleaseManifest:
    release_id: str
    version: str
    environment: DeploymentEnvironment
    status: ReleaseStatus
    components: dict[str, str]  # component_id -> version
    validation_runs: tuple[str, ...]
    approval_records: tuple[str, ...]
    readiness_gates: tuple[dict[str, Any], ...] = ()
    created_by: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    manifest_digest: str = ""
    promoted_by: str | None = None
    promoted_at: datetime | None = None
    rollback_target_id: str | None = None
    has_blocking_incidents: bool = False
    has_active_suspensions: bool = False
    readiness_assessment: ReadinessAssessment | None = None

    def __post_init__(self) -> None:
        if not self.manifest_digest:
            payload = self._compute_digest_payload()
            digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            object.__setattr__(self, "manifest_digest", digest)

    def _compute_digest_payload(self) -> str:
        gates_summary = ",".join(
            sorted(
                f"{g.get('gate_name')}:{g.get('status')}"
                for g in self.readiness_gates
                if isinstance(g, dict) and "gate_name" in g
            )
        )
        return (
            f"{self.release_id}:{self.version}:{self.environment.value}:"
            f"{json.dumps(self.components, sort_keys=True)}:"
            f"{','.join(sorted(self.validation_runs))}:{','.join(sorted(self.approval_records))}:"
            f"{gates_summary}"
        )

    def verify_manifest_integrity(self) -> bool:
        expected = hashlib.sha256(self._compute_digest_payload().encode("utf-8")).hexdigest()
        return self.manifest_digest == expected

    def validate_promotion_eligibility(
        self,
        *,
        has_active_suspensions: bool | None = None,
        has_blocking_incidents: bool | None = None,
    ) -> tuple[bool, list[str]]:
        """Validates all strict bank production promotion conditions.
        
        Enforces:
        1. Manifest cryptographic integrity verified.
        2. Release status is APPROVED or STAGED.
        3. Mandatory components exist with specified versions.
        4. Independent validation runs exist.
        5. Maker/checker approval records exist.
        6. All 13 mandatory readiness gates evaluated and PASS.
        7. No blocking incidents active.
        8. No active kill-switch suspensions on release components.
        """
        reasons: list[str] = []

        active_susp = self.has_active_suspensions if has_active_suspensions is None else has_active_suspensions
        active_inc = self.has_blocking_incidents if has_blocking_incidents is None else has_blocking_incidents

        # 1. Manifest digest integrity
        if not self.verify_manifest_integrity():
            reasons.append("Deployment manifest cryptographic digest verification failed (tamper detected)")

        # 2. Release status
        if self.status not in (ReleaseStatus.APPROVED, ReleaseStatus.STAGED):
            reasons.append(f"Release status must be APPROVED or STAGED for production, got '{self.status.value}'")

        # 3. Components
        if not self.components:
            reasons.append("Release manifest defines no governed components")
        for comp_id, comp_ver in self.components.items():
            if not comp_ver or not comp_ver.strip():
                reasons.append(f"Component '{comp_id}' has an invalid or empty version")

        # 4. Validation runs
        if not self.validation_runs:
            reasons.append("No independent validation run records attached to this release")

        # 5. Maker/checker approvals
        if not self.approval_records:
            reasons.append("No dual-control maker/checker approval records attached to this release")

        # 6. 13 Mandatory readiness gates
        evaluated_gate_statuses: dict[str, str] = {}
        if self.readiness_assessment:
            for g in self.readiness_assessment.gates:
                evaluated_gate_statuses[g.gate_name] = g.status.value
        else:
            for g in self.readiness_gates:
                if isinstance(g, dict) and "gate_name" in g and "status" in g:
                    evaluated_gate_statuses[g["gate_name"]] = str(g["status"])

        for mandatory_gate in MANDATORY_GATES:
            gate_stat = evaluated_gate_statuses.get(mandatory_gate)
            if gate_stat is None:
                reasons.append(f"Mandatory readiness gate '{mandatory_gate}' has not been evaluated")
            elif gate_stat != GateStatus.PASS.value:
                reasons.append(f"Mandatory readiness gate '{mandatory_gate}' is {gate_stat} (requires PASS)")

        # 7. Blocking incidents
        if active_inc:
            reasons.append("Release cannot be promoted while blocking production incidents remain open")

        # 8. Active suspensions
        if active_susp:
            reasons.append("Release cannot be promoted while active kill switch component suspensions exist")

        return len(reasons) == 0, reasons

    def can_promote_to_production(self) -> bool:
        """Production deployment requires all 8 strict governance gates to pass."""
        eligible, _ = self.validate_promotion_eligibility()
        return eligible


def can_promote_to_production(manifest: ProductionReleaseManifest) -> bool:
    return manifest.can_promote_to_production()


def validate_promotion_eligibility(manifest: ProductionReleaseManifest) -> tuple[bool, list[str]]:
    return manifest.validate_promotion_eligibility()

