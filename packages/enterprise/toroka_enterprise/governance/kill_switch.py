from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol, runtime_checkable


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


@runtime_checkable
class KillSwitchStore(Protocol):
    """Protocol for persistent storage of component suspensions."""

    def get_active_suspension(self, component_id: str, version: str) -> SuspensionRecord | None:
        ...

    def list_active_suspensions(self) -> list[SuspensionRecord]:
        ...

    def record_suspension(self, record: SuspensionRecord) -> None:
        ...

    def record_resume(self, record: SuspensionRecord) -> None:
        ...


class InMemoryKillSwitchStore:
    """Default in-memory store for kill switch records."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, str], SuspensionRecord] = {}

    def get_active_suspension(self, component_id: str, version: str) -> SuspensionRecord | None:
        rec = self._records.get((component_id, version))
        if rec and rec.is_active:
            return rec
        return None

    def list_active_suspensions(self) -> list[SuspensionRecord]:
        return [r for r in self._records.values() if r.is_active]

    def record_suspension(self, record: SuspensionRecord) -> None:
        self._records[(record.component_id, record.component_version)] = record

    def record_resume(self, record: SuspensionRecord) -> None:
        self._records[(record.component_id, record.component_version)] = record


class KillSwitch:
    """Manages component-level suspension and rapid fault isolation with persistent store backing."""

    def __init__(self, store: KillSwitchStore | None = None) -> None:
        self._store: KillSwitchStore = store if store is not None else InMemoryKillSwitchStore()

    @property
    def store(self) -> KillSwitchStore:
        return self._store

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
        self._store.record_suspension(record)
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
        prev = self._store.get_active_suspension(component_id, version)
        if prev is None:
            raise ValueError(f"Component {component_id}:{version} is not currently suspended")
        if not actor or not actor.strip():
            raise ValueError("Resume requires an authenticated actor")
        if not reason or not reason.strip():
            raise ValueError("Resume requires a reason")

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
        self._store.record_resume(updated)
        return updated

    def is_suspended(self, component_id: str, version: str) -> bool:
        return self._store.get_active_suspension(component_id, version) is not None

    def assert_active(self, component_id: str, version: str) -> None:
        rec = self._store.get_active_suspension(component_id, version)
        if rec is not None:
            raise ComponentSuspended(
                f"Component '{component_id}:{version}' is suspended by {rec.suspended_by}. "
                f"Reason: {rec.reason}"
            )

    def get_active_suspensions(self) -> list[SuspensionRecord]:
        return self._store.list_active_suspensions()
