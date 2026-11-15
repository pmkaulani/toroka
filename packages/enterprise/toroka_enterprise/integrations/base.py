"""Base connector interfaces, contexts, and batch protocols."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from .contracts import CanonicalRecord, SourceSystem


@dataclass(frozen=True, slots=True)
class ConnectorContext:
    """Execution context and resume position for a connector sync job."""
    installation_id: str
    connector_id: str
    cursor: str | None = None
    since: datetime | None = None
    batch_size: int = 500
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ConnectorBatch:
    """A batch of normalized canonical records returned by a connector."""
    records: list[CanonicalRecord]
    next_cursor: str | None
    has_more: bool
    records_read: int = 0


class BankConnector(Protocol):
    """Protocol implemented by all bank system adapters (REST, File, DB, Stream)."""

    @property
    def connector_id(self) -> str:
        """Unique identifier of the connector instance."""
        ...

    @property
    def connector_type(self) -> str:
        """Type of connector (e.g. rest_api, sftp_file, database_query, signed_event)."""
        ...

    @property
    def source_system(self) -> SourceSystem:
        """Categorical bank subsystem being integrated."""
        ...

    @property
    def version(self) -> str:
        """Connector implementation version."""
        ...

    async def healthcheck(self) -> bool:
        """Probe the upstream bank system to verify connectivity and credentials."""
        ...

    async def fetch_batch(self, context: ConnectorContext) -> ConnectorBatch:
        """Retrieve the next batch of canonical records starting from context.cursor."""
        ...

    async def fetch_events(self, context: ConnectorContext) -> list[CanonicalRecord]:
        """Optional streaming/event poll hook for near-real-time connectors."""
        ...

    async def close(self) -> None:
        """Clean up underlying connections, pools, and sessions."""
        ...

    @property
    def metadata(self) -> dict[str, Any]:
        """Non-sensitive connector configuration and target system information."""
        ...

    @property
    def capabilities(self) -> dict[str, Any]:
        """Declared integration capabilities (pagination, backfill, filtering)."""
        ...
