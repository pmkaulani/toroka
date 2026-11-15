# Toroka Enterprise — Bank Connector Developer Guide

## 1. Overview & Connector Protocol

All source connectors in Toroka implement the `BankConnector` protocol defined in `packages/enterprise/toroka_enterprise/integrations/base.py`.

Whether integrating with a proprietary in-house payment switch, an enterprise data lake, or a mainframe batch export, developers follow a standardized lifecycle:

```python
@runtime_checkable
class BankConnector(Protocol):
    connector_id: str
    connector_type: str
    source_system: SourceSystem
    version: str
    metadata: dict[str, Any]
    capabilities: dict[str, Any]

    async def healthcheck(self) -> bool:
        """Verify connectivity, network routes, and credentials."""
        ...

    async def fetch_batch(self, context: ConnectorContext) -> ConnectorBatch:
        """Pull a batch of records starting at the provided cursor."""
        ...

    async def fetch_events(self, context: ConnectorContext) -> list[CanonicalRecord]:
        """Optionally pull real-time delta events."""
        ...

    async def close(self) -> None:
        """Clean up connection pools and network sockets."""
        ...
```

---

## 2. Implementing a Custom Connector

### Step 1: Subclass and Define Capabilities
```python
from toroka_enterprise.integrations.base import BankConnector, ConnectorBatch, ConnectorContext
from toroka_enterprise.integrations.contracts import SourceSystem

class CustomPaymentConnector:
    def __init__(self, connector_id: str, endpoint_url: str):
        self.connector_id = connector_id
        self.connector_type = "rest_api"
        self.source_system = SourceSystem.PAYMENT_SWITCH
        self.version = "1.0.0"
        self.endpoint_url = endpoint_url
        self.metadata = {"name": "Custom RTGS/SWIFT Gateway"}
        self.capabilities = {"supports_cursors": True, "batch_size_max": 1000}

    async def healthcheck(self) -> bool:
        # Ping the health or metadata endpoint
        return True

    async def fetch_batch(self, context: ConnectorContext) -> ConnectorBatch:
        cursor = context.cursor
        # 1. Fetch raw batch from bank system
        # 2. Normalize raw dictionaries into CanonicalTransactionRecord
        # 3. Return ConnectorBatch with records, next_cursor, has_more
        return ConnectorBatch(
            records=canonical_records,
            next_cursor=new_cursor,
            has_more=has_more,
            records_read=len(canonical_records),
        )

    async def close(self) -> None:
        pass
```

### Step 2: Handle Edge Cases
1. **SSRF Defense**: Restrict HTTP endpoints to pre-approved internal domains (`allowed_hosts`).
2. **Rate Limits**: Catch HTTP 429 status codes and raise `ConnectorRateLimitError` with backoff seconds.
3. **Invalid Timestamps**: Use `parse_timestamp()` from `mapping.py` to support standard banking formats without throwing unhandled exceptions.

### Step 3: Register Connector
Register your connector instance with the installation registry:
```python
from toroka_enterprise.integrations.registry import DEFAULT_CONNECTOR_REGISTRY

DEFAULT_CONNECTOR_REGISTRY.register(
    installation_id="toroka-default-installation",
    connector=my_connector_instance,
    enabled=True,
)
```
