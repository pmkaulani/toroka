# Toroka Enterprise — Real-Time Signed Event Webhooks

## 1. Overview & Event-Driven Architecture

In addition to scheduled batch extraction, Toroka Enterprise supports real-time event ingestion via signed webhooks. When sensitive operational events occur (e.g. dormant account activation, employee privilege escalation, large cash balancing posting), bank systems can push signed event notifications directly to:

`POST /api/enterprise/v1/integrations/events`

---

## 2. Authentication & Cryptographic Verification

All incoming events require two HTTP headers:
- `X-Connector-ID`: Identifier of the registered `BankEventConnector`.
- `X-Signature`: Hex-encoded HMAC-SHA256 signature calculated over the raw request payload using the pre-shared connector secret key.

```
Signature = HMAC_SHA256(secret_key, raw_http_body)
```

### 2.1 Clock-Skew Tolerance
Each event payload must include a unix timestamp. `BankEventConnector` verifies that:
```python
abs(current_unix_time - payload["timestamp"]) <= timestamp_tolerance_seconds (default 300s)
```
Events with timestamps in the past beyond the tolerance window or in the future are rejected with HTTP 401.

---

## 3. Replay Protection & Inbox Semantics

Incoming events are tracked in `enterprise_integration_events_inbox`:
- **First Delivery**: Signature verified -> Inbox row created (`status="received"`) -> Canonical translation -> Ingested into canonical store -> HTTP 201 Created (`status="processed"`).
- **Duplicate / Retried Delivery**: If an event with the same `(event_id, installation_id, connector_id)` arrives again, Toroka recognizes it as a replay, verifies the signature, and returns HTTP 200 OK (`status="duplicate_acknowledged"`) without duplicate ingestion.
