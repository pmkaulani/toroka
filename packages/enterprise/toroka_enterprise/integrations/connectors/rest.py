"""REST API connector for core banking and enterprise platforms."""
from __future__ import annotations

import logging
from typing import Any, Callable
from urllib.parse import urlparse
import httpx

from ..base import BankConnector, ConnectorBatch, ConnectorContext
from ..contracts import CanonicalRecord, SourceSystem
from ..exceptions import (
    ConnectorAuthenticationError,
    ConnectorNetworkError,
    ConnectorRateLimitError,
    SSRFProtectionError,
)
from ..mapping import map_core_banking_transaction

logger = logging.getLogger(__name__)


class BankRestConnector:
    """REST API connector with pagination, rate limiting, and SSRF protection."""

    def __init__(
        self,
        *,
        connector_id: str,
        base_url: str,
        endpoint_path: str = "/api/v1/transactions",
        source_system: SourceSystem = SourceSystem.CORE_BANKING,
        bearer_token: str | None = None,
        api_key: str | None = None,
        timeout: float = 10.0,
        allowed_hosts: tuple[str, ...] | None = None,
        client: httpx.AsyncClient | None = None,
        record_mapper: Callable[[dict[str, Any], str, str], CanonicalRecord] | None = None,
    ):
        self._connector_id = connector_id
        self._base_url = base_url.rstrip("/")
        self._endpoint_path = endpoint_path
        self._source_system = source_system
        self._bearer_token = bearer_token
        self._api_key = api_key
        self._timeout = timeout
        self._allowed_hosts = allowed_hosts
        self._custom_client = client
        self._mapper = record_mapper or (lambda raw, inst, conn: map_core_banking_transaction(raw, installation_id=inst, connector_id=conn))

        self._validate_destination(self._base_url)

    def _validate_destination(self, url: str) -> None:
        """Validate destination URL against SSRF rules and domain allowlists."""
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise SSRFProtectionError(f"Unsupported URL scheme: {parsed.scheme}")
        host = parsed.hostname or ""
        if self._allowed_hosts and host not in self._allowed_hosts:
            raise SSRFProtectionError(f"Destination host '{host}' not in allowed hosts allowlist")

    @property
    def connector_id(self) -> str:
        return self._connector_id

    @property
    def connector_type(self) -> str:
        return "rest_api"

    @property
    def source_system(self) -> SourceSystem:
        return self._source_system

    @property
    def version(self) -> str:
        return "1.0.0"

    def _get_headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "Toroka-Enterprise-Integration/1.0",
        }
        if self._bearer_token:
            headers["Authorization"] = f"Bearer {self._bearer_token}"
        elif self._api_key:
            headers["X-API-Key"] = self._api_key
        return headers

    async def _get_client(self) -> httpx.AsyncClient:
        if self._custom_client is not None:
            return self._custom_client
        return httpx.AsyncClient(timeout=self._timeout)

    async def healthcheck(self) -> bool:
        """Probe upstream health endpoint."""
        url = f"{self._base_url}/health"
        try:
            client = await self._get_client()
            resp = await client.get(url, headers=self._get_headers())
            return resp.status_code in (200, 204)
        except Exception:
            return False

    async def fetch_batch(self, context: ConnectorContext) -> ConnectorBatch:
        """Fetch next batch of records from upstream REST API using cursor or page."""
        url = f"{self._base_url}{self._endpoint_path}"
        params: dict[str, Any] = {"limit": context.batch_size}
        if context.cursor:
            params["cursor"] = context.cursor
        if context.since:
            params["since"] = context.since.isoformat()

        client = await self._get_client()
        try:
            resp = await client.get(url, params=params, headers=self._get_headers())
        except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.NetworkError) as exc:
            raise ConnectorNetworkError(f"Network error contacting bank REST API: {exc}") from exc

        if resp.status_code in (401, 403):
            raise ConnectorAuthenticationError(f"Authentication failed for connector '{self._connector_id}': HTTP {resp.status_code}")
        if resp.status_code == 429:
            raise ConnectorRateLimitError(f"Rate limit exceeded on bank REST API for connector '{self._connector_id}'")
        if resp.status_code != 200:
            raise ConnectorNetworkError(f"Bank REST API returned error {resp.status_code}: {resp.text}")

        data = resp.json()
        raw_items = data.get("items") or data.get("records") or []
        next_cursor = data.get("next_cursor")
        has_more = bool(data.get("has_more", False) or (next_cursor and len(raw_items) > 0))

        canonical_records: list[CanonicalRecord] = []
        for raw in raw_items:
            rec = self._mapper(raw, context.installation_id, self._connector_id)
            canonical_records.append(rec)

        return ConnectorBatch(
            records=canonical_records,
            next_cursor=next_cursor,
            has_more=has_more,
            records_read=len(raw_items),
        )

    async def fetch_events(self, context: ConnectorContext) -> list[CanonicalRecord]:
        return []

    async def close(self) -> None:
        if self._custom_client is not None and not self._custom_client.is_closed:
            await self._custom_client.aclose()

    @property
    def metadata(self) -> dict[str, Any]:
        return {
            "connector_id": self._connector_id,
            "connector_type": self.connector_type,
            "source_system": self._source_system.value,
            "base_url": self._base_url,
            "endpoint_path": self._endpoint_path,
        }

    @property
    def capabilities(self) -> dict[str, Any]:
        return {
            "batch_pagination": True,
            "cursor_resumption": True,
            "incremental_since": True,
            "streaming": False,
        }
