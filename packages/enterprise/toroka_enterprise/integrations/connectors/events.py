"""Signed webhook event connector with HMAC verification and replay protection."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from typing import Any, Callable

from ..base import BankConnector, ConnectorBatch, ConnectorContext
from ..contracts import CanonicalRecord, SourceSystem
from ..exceptions import ReplayError, SchemaValidationError
from ..mapping import map_core_banking_transaction

logger = logging.getLogger(__name__)


def verify_hmac_signature(
    body: bytes,
    supplied_signature: str,
    secret: bytes,
) -> bool:
    """Verify HMAC-SHA256 signature using constant-time comparison."""
    expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
    # Support both bare hex and 'sha256=' prefix
    normalized = supplied_signature.removeprefix("sha256=")
    return hmac.compare_digest(expected, normalized)


class BankEventConnector:
    """Connector receiving and verifying signed real-time events from bank systems."""

    def __init__(
        self,
        *,
        connector_id: str,
        secret_key: bytes,
        source_system: SourceSystem = SourceSystem.CBS_AUDIT,
        timestamp_tolerance_seconds: int = 300,
        record_mapper: Callable[[dict[str, Any], str, str], CanonicalRecord] | None = None,
    ):
        self._connector_id = connector_id
        self._secret_key = secret_key
        self._source_system = source_system
        self._tolerance = timestamp_tolerance_seconds
        self._mapper = record_mapper or (lambda raw, inst, conn: map_core_banking_transaction(raw, installation_id=inst, connector_id=conn))

    @property
    def connector_id(self) -> str:
        return self._connector_id

    @property
    def connector_type(self) -> str:
        return "signed_event"

    @property
    def source_system(self) -> SourceSystem:
        return self._source_system

    @property
    def version(self) -> str:
        return "1.0.0"

    async def healthcheck(self) -> bool:
        return bool(self._secret_key and len(self._secret_key) >= 16)

    def verify_and_parse_event(
        self,
        body: bytes,
        signature: str,
        installation_id: str,
    ) -> tuple[str, str, CanonicalRecord]:
        """Verify HMAC signature and timestamp freshness, and map event payload to CanonicalRecord."""
        if not verify_hmac_signature(body, signature, self._secret_key):
            raise ReplayError("Invalid HMAC event signature")

        try:
            data = json.loads(body.decode("utf-8"))
        except Exception as exc:
            raise SchemaValidationError(f"Invalid event JSON body: {exc}") from exc

        event_id = str(data.get("event_id") or "").strip()
        if not event_id:
            raise SchemaValidationError("Event missing required event_id")

        ts = data.get("timestamp")
        if ts is not None:
            now = int(time.time())
            if abs(now - int(ts)) > self._tolerance:
                raise ReplayError(f"Event timestamp expired or clock skewed beyond {self._tolerance}s")

        event_type = str(data.get("event_type") or "EVENT")
        payload = data.get("payload") or {}

        rec = self._mapper(payload, installation_id, self._connector_id)
        return event_id, event_type, rec

    async def fetch_batch(self, context: ConnectorContext) -> ConnectorBatch:
        return ConnectorBatch(records=[], next_cursor=context.cursor, has_more=False)

    async def fetch_events(self, context: ConnectorContext) -> list[CanonicalRecord]:
        return []

    async def close(self) -> None:
        pass

    @property
    def metadata(self) -> dict[str, Any]:
        return {
            "connector_id": self._connector_id,
            "connector_type": self.connector_type,
            "source_system": self._source_system.value,
            "timestamp_tolerance": self._tolerance,
        }

    @property
    def capabilities(self) -> dict[str, Any]:
        return {
            "batch_pagination": False,
            "cursor_resumption": False,
            "hmac_signing": True,
            "streaming": True,
        }
