from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from .readiness import ReadinessAssessment, MANDATORY_GATES, GateStatus


def _canonical_utc(value: datetime) -> str:
    # SQL backends may return naive datetimes. Treat those as UTC consistently.
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def release_manifest_payload(
    *,
    release_id: str,
    version: str,
    components: dict[str, str],
    validation_runs: tuple[str, ...] | list[str],
    approval_records: tuple[str, ...] | list[str],
    readiness_gates: tuple[dict[str, Any], ...] | list[dict[str, Any]],
    created_by: str,
    created_at: datetime,
) -> dict[str, Any]:
    # Do not include environment/status/promoted_by/promoted_at: these are mutable
    # lifecycle fields and would invalidate the immutable release-content digest.
    gates = sorted(
        (dict(g) for g in readiness_gates),
        key=lambda g: (str(g.get("gate_name", "")), canonical_json(g)),
    )
    return {
        "schema": "toroka.release-manifest.v1",
        "release_id": release_id,
        "version": version,
        "components": dict(sorted(components.items())),
        "validation_runs": sorted(set(validation_runs)),
        "approval_records": sorted(set(approval_records)),
        "readiness_gates": gates,
        "created_by": created_by,
        "created_at": _canonical_utc(created_at),
    }


def compute_release_manifest_digest(payload: dict[str, Any] | None = None, **kwargs: Any) -> str:
    if payload is None:
        payload = release_manifest_payload(**kwargs)
    raw = canonical_json(payload).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


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
        if not self.readiness_gates and self.readiness_assessment:
            gates_data = tuple(
                {
                    "gate_name": g.gate_name,
                    "status": g.status.value,
                    "verified_by": g.verified_by,
                    "rationale": g.rationale,
                    "evidence_reference": g.evidence_reference,
                }
                for g in self.readiness_assessment.gates
            )
            object.__setattr__(self, "readiness_gates", gates_data)

        if not self.manifest_digest:
            digest = compute_release_manifest_digest(
                release_id=self.release_id,
                version=self.version,
                components=self.components,
                validation_runs=self.validation_runs,
                approval_records=self.approval_records,
                readiness_gates=self.readiness_gates,
                created_by=self.created_by,
                created_at=self.created_at,
            )
            object.__setattr__(self, "manifest_digest", digest)

    def _compute_digest_payload(self) -> str:
        return canonical_json(
            release_manifest_payload(
                release_id=self.release_id,
                version=self.version,
                components=self.components,
                validation_runs=self.validation_runs,
                approval_records=self.approval_records,
                readiness_gates=self.readiness_gates,
                created_by=self.created_by,
                created_at=self.created_at,
            )
        )

    def verify_manifest_integrity(self) -> bool:
        expected = hashlib.sha256(self._compute_digest_payload().encode("utf-8")).hexdigest()
        return hmac.compare_digest(self.manifest_digest, expected)

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
            elif str(gate_stat).upper() != GateStatus.PASS.value:
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

