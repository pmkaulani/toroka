"""Connector registry managing connector instances, state, and discovery."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .base import BankConnector

logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class RegisteredConnectorInfo:
    connector: BankConnector
    installation_id: str
    enabled: bool = True
    registered_at: datetime = field(default_factory=utc_now)
    last_health_status: bool = True
    last_health_check_at: datetime | None = None


class ConnectorRegistry:
    """Installation-scoped in-memory registry of approved connector implementations."""

    def __init__(self):
        # (installation_id, connector_id) -> RegisteredConnectorInfo
        self._connectors: dict[tuple[str, str], RegisteredConnectorInfo] = {}

    def register(
        self,
        installation_id: str,
        connector: BankConnector,
        enabled: bool = True,
    ) -> None:
        """Register an approved bank connector instance for an installation."""
        key = (installation_id, connector.connector_id)
        if key in self._connectors:
            logger.info("Updating existing connector registration '%s' for installation '%s'", connector.connector_id, installation_id)
        self._connectors[key] = RegisteredConnectorInfo(
            connector=connector,
            installation_id=installation_id,
            enabled=enabled,
        )

    def get(self, installation_id: str, connector_id: str) -> BankConnector | None:
        info = self._connectors.get((installation_id, connector_id))
        return info.connector if info else None

    def get_info(self, installation_id: str, connector_id: str) -> RegisteredConnectorInfo | None:
        return self._connectors.get((installation_id, connector_id))

    def list_connectors(self, installation_id: str) -> list[RegisteredConnectorInfo]:
        return [
            info for (inst, _), info in self._connectors.items()
            if inst == installation_id
        ]

    def set_enabled(self, installation_id: str, connector_id: str, enabled: bool) -> bool:
        info = self._connectors.get((installation_id, connector_id))
        if info is None:
            return False
        info.enabled = enabled
        return True

    def unregister(self, installation_id: str, connector_id: str) -> bool:
        key = (installation_id, connector_id)
        if key in self._connectors:
            del self._connectors[key]
            return True
        return False


# Global default registry instance
DEFAULT_CONNECTOR_REGISTRY = ConnectorRegistry()
