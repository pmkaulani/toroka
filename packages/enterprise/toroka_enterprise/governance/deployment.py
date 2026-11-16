from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any
from .readiness import ReadinessAssessment


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
    created_at: datetime = field(default_factory=datetime.utcnow)
    manifest_digest: str = ""
    promoted_by: str | None = None
    promoted_at: datetime | None = None
    rollback_target_id: str | None = None

    def __post_init__(self) -> None:
        if not self.manifest_digest:
            payload = (
                f"{self.release_id}:{self.version}:{self.environment.value}:"
                f"{json.dumps(self.components, sort_keys=True)}:"
                f"{','.join(self.validation_runs)}:{','.join(self.approval_records)}"
            )
            digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            object.__setattr__(self, "manifest_digest", digest)

    def can_promote_to_production(self) -> bool:
        """Production deployment requires APPROVED or STAGED status and validation evidence."""
        if self.status not in (ReleaseStatus.APPROVED, ReleaseStatus.STAGED):
            return False
        if not self.validation_runs:
            return False
        if not self.approval_records:
            return False
        return True


def can_promote_to_production(manifest: ProductionReleaseManifest) -> bool:
    return manifest.can_promote_to_production()
