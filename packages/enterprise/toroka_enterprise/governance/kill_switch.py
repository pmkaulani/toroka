from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class SuspensionRecord:
    component_id: str
    component_version: str
    suspended_by: str
    suspended_at: datetime
    reason: str
    incident_id: str | None = None
    automatic: bool = False
    resumed_by: str | None = None
    resumed_at: datetime | None = None
    resume_reason: str | None = None

    @property
    def is_active(self) -> bool:
        return self.resumed_at is None


class ComponentSuspended(Exception):
    pass


class KillSwitch:
    """Manages component-level suspension and rapid fault isolation."""

    def __init__(self) -> None:
        self._suspended: dict[tuple[str, str], SuspensionRecord] = {}

    def suspend(
        self,
        *,
        component_id: str,
        version: str,
        actor: str,
        reason: str,
        incident_id: str | None = None,
        now: datetime,
        automatic: bool = False,
    ) -> SuspensionRecord:
        if not actor or not actor.strip():
            raise ValueError("Suspension requires an authenticated actor")
        if not reason or not reason.strip():
            raise ValueError("Suspension requires a reason")

        record = SuspensionRecord(
            component_id=component_id,
            component_version=version,
            suspended_by=actor,
            suspended_at=now,
            reason=reason,
            incident_id=incident_id,
            automatic=automatic,
        )
        self._suspended[(component_id, version)] = record
        return record

    def resume(
        self,
        *,
        component_id: str,
        version: str,
        actor: str,
        reason: str,
        now: datetime,
    ) -> SuspensionRecord:
        key = (component_id, version)
        if key not in self._suspended or not self._suspended[key].is_active:
            raise ValueError(f"Component {component_id}:{version} is not currently suspended")
        if not actor or not actor.strip():
            raise ValueError("Resume requires an authenticated actor")
        if not reason or not reason.strip():
            raise ValueError("Resume requires a reason")

        prev = self._suspended[key]
        updated = SuspensionRecord(
            component_id=prev.component_id,
            component_version=prev.component_version,
            suspended_by=prev.suspended_by,
            suspended_at=prev.suspended_at,
            reason=prev.reason,
            incident_id=prev.incident_id,
            automatic=prev.automatic,
            resumed_by=actor,
            resumed_at=now,
            resume_reason=reason,
        )
        self._suspended[key] = updated
        return updated

    def is_suspended(self, component_id: str, version: str) -> bool:
        key = (component_id, version)
        rec = self._suspended.get(key)
        return rec is not None and rec.is_active

    def assert_active(self, component_id: str, version: str) -> None:
        if self.is_suspended(component_id, version):
            rec = self._suspended[(component_id, version)]
            raise ComponentSuspended(
                f"Component '{component_id}:{version}' is suspended by {rec.suspended_by}. "
                f"Reason: {rec.reason}"
            )

    def get_active_suspensions(self) -> list[SuspensionRecord]:
        return [rec for rec in self._suspended.values() if rec.is_active]
