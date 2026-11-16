from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any
from .models import (
    ComponentType,
    GovernanceStatus,
    GovernedComponent,
    RiskTier,
)


class RegistryError(Exception):
    pass


class ComponentRegistry:
    """Enterprise registry of all versioned rules, detectors, models, prompts, and policies."""

    def __init__(self) -> None:
        self._components: dict[tuple[str, str], GovernedComponent] = {}

    def register(self, component: GovernedComponent) -> GovernedComponent:
        key = (component.component_id, component.version)
        if key in self._components:
            raise RegistryError(f"Component '{component.component_id}:{component.version}' is already registered")
        self._components[key] = component
        return component

    def get(self, component_id: str, version: str) -> GovernedComponent:
        key = (component_id, version)
        if key not in self._components:
            raise RegistryError(f"Component '{component_id}:{version}' not found")
        return self._components[key]

    def list_components(
        self,
        component_type: ComponentType | None = None,
        status: GovernanceStatus | None = None,
    ) -> list[GovernedComponent]:
        items = list(self._components.values())
        if component_type:
            items = [c for c in items if c.component_type == component_type]
        if status:
            items = [c for c in items if c.status == status]
        return items

    def transition_status(
        self,
        component_id: str,
        version: str,
        new_status: GovernanceStatus,
        *,
        actor: str,
        now: datetime,
    ) -> GovernedComponent:
        comp = self.get(component_id, version)

        # Invariant checks
        if new_status == GovernanceStatus.ACTIVE:
            if not comp.approved_at or not comp.approved_by:
                raise RegistryError("Cannot activate an unapproved component")

        updates: dict[str, Any] = {"status": new_status}
        if new_status == GovernanceStatus.SUSPENDED:
            updates["suspended_at"] = now
            updates["suspended_by"] = actor
        elif new_status == GovernanceStatus.RETIRED:
            updates["retired_at"] = now
            updates["retired_by"] = actor

        updated_comp = replace(comp, **updates)
        self._components[(component_id, version)] = updated_comp
        return updated_comp

    def get_active_manifest(self) -> dict[str, str]:
        """Returns map of component_id to active version for all currently ACTIVE components."""
        return {
            c.component_id: c.version
            for c in self._components.values()
            if c.status == GovernanceStatus.ACTIVE
        }
