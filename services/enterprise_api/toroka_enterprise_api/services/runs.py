"""Investigation run manifest persistence and query service."""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from ..auth import EnterprisePrincipal
from ..permissions import BANK_ROLES
from ..persistence.audit import append_audit
from ..persistence.models import RunRecord
from ..persistence.repositories import RunRepository


class RunService:
    def __init__(self, db: Session):
        self.db = db
        self.runs = RunRepository(db)

    def list_runs(
        self,
        principal: EnterprisePrincipal,
        installation_id: str | None = None,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[RunRecord]:
        if not principal.roles.intersection(BANK_ROLES):
            raise PermissionError("Permission denied.")
        return self.runs.list_runs(installation_id=installation_id, limit=limit, offset=offset)

    def get_run(
        self,
        principal: EnterprisePrincipal,
        manifest_id: str,
        installation_id: str | None = None,
    ) -> RunRecord:
        if not principal.roles.intersection(BANK_ROLES):
            raise PermissionError("Permission denied.")
        run = self.runs.get_by_manifest_id(manifest_id, installation_id=installation_id)
        if run is None:
            raise LookupError(f"Run manifest '{manifest_id}' not found")
        return run

    def record_run(
        self,
        principal: EnterprisePrincipal,
        *,
        installation_id: str,
        manifest: dict[str, Any],
        result_digest: str | None = None,
        status: str = "completed",
    ) -> RunRecord:
        manifest_id = manifest.get("manifest_id")
        if not manifest_id:
            raise ValueError("Manifest dictionary must contain 'manifest_id'")

        existing = self.runs.get_by_manifest_id(manifest_id, installation_id=installation_id)
        if existing:
            return existing

        run = RunRecord(
            installation_id=installation_id,
            manifest_id=manifest_id,
            manifest=manifest,
            result_digest=result_digest,
            status=status,
            created_by=principal.subject,
        )
        self.runs.create(run)

        append_audit(
            self.db,
            installation_id=installation_id,
            actor_subject=principal.subject,
            actor_role="system_administrator" if "system_administrator" in principal.roles else "data_steward",
            action="run_manifest_recorded",
            target_type="run",
            target_id=manifest_id,
            safe_metadata={
                "manifest_id": manifest_id,
                "status": status,
            },
        )
        self.db.commit()
        return run
