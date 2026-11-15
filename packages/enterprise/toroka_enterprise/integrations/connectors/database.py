"""Read-only database connector for approved bank reporting views and replicas."""
from __future__ import annotations

import logging
from typing import Any, Callable
from sqlalchemy import text
from sqlalchemy.engine import Engine

from ..base import BankConnector, ConnectorBatch, ConnectorContext
from ..contracts import CanonicalRecord, SourceSystem
from ..exceptions import SchemaValidationError
from ..mapping import map_core_banking_transaction

logger = logging.getLogger(__name__)


class BankDatabaseConnector:
    """Read-only database connector executing parameterized queries against approved views."""

    def __init__(
        self,
        *,
        connector_id: str,
        engine: Engine,
        view_name: str,
        cursor_column: str = "id",
        source_system: SourceSystem = SourceSystem.CORE_BANKING,
        allowed_views: tuple[str, ...] | None = None,
        record_mapper: Callable[[dict[str, Any], str, str], CanonicalRecord] | None = None,
    ):
        self._connector_id = connector_id
        self._engine = engine
        self._view_name = view_name
        self._cursor_column = cursor_column
        self._source_system = source_system
        self._allowed_views = allowed_views or (view_name,)
        self._mapper = record_mapper or (lambda raw, inst, conn: map_core_banking_transaction(raw, installation_id=inst, connector_id=conn))

        if self._view_name not in self._allowed_views:
            raise SchemaValidationError(f"View '{self._view_name}' is not in the allowed views list")

    @property
    def connector_id(self) -> str:
        return self._connector_id

    @property
    def connector_type(self) -> str:
        return "database_query"

    @property
    def source_system(self) -> SourceSystem:
        return self._source_system

    @property
    def version(self) -> str:
        return "1.0.0"

    async def healthcheck(self) -> bool:
        """Verify read-only connection to database."""
        try:
            with self._engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return True
        except Exception:
            return False

    async def fetch_batch(self, context: ConnectorContext) -> ConnectorBatch:
        """Execute parameterized read query using incremental cursor."""
        query_str = (
            f"SELECT * FROM {self._view_name} "
            f"WHERE (:cursor IS NULL OR {self._cursor_column} > :cursor) "
            f"ORDER BY {self._cursor_column} ASC "
            f"LIMIT :limit"
        )

        with self._engine.connect() as conn:
            cursor_val = context.cursor if context.cursor else None
            result = conn.execute(
                text(query_str),
                {"cursor": cursor_val, "limit": context.batch_size},
            )
            rows = [dict(row._mapping) for row in result]

        records: list[CanonicalRecord] = []
        next_cursor = None
        for row in rows:
            rec = self._mapper(row, context.installation_id, self._connector_id)
            records.append(rec)
            next_cursor = str(row.get(self._cursor_column, ""))

        has_more = len(rows) == context.batch_size
        return ConnectorBatch(
            records=records,
            next_cursor=next_cursor if rows else context.cursor,
            has_more=has_more,
            records_read=len(rows),
        )

    async def fetch_events(self, context: ConnectorContext) -> list[CanonicalRecord]:
        return []

    async def close(self) -> None:
        self._engine.dispose()

    @property
    def metadata(self) -> dict[str, Any]:
        return {
            "connector_id": self._connector_id,
            "connector_type": self.connector_type,
            "source_system": self._source_system.value,
            "view_name": self._view_name,
            "cursor_column": self._cursor_column,
        }

    @property
    def capabilities(self) -> dict[str, Any]:
        return {
            "batch_pagination": True,
            "cursor_resumption": True,
            "incremental_since": False,
            "streaming": False,
        }
