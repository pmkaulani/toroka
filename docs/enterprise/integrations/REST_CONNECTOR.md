# Toroka Enterprise — REST API Connector Specification

## 1. Overview & Capabilities

`BankRestConnector` connects to modern banking microservices, payment gateways, and core banking REST interfaces. It handles pagination, token authentication, rate limiting, and network failures.

## 2. Configuration Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `connector_id` | `str` | Yes | Unique connector identifier |
| `base_url` | `str` | Yes | Base URL for the bank API (e.g. `https://cbs-api.bank.internal`) |
| `api_path` | `str` | No | Resource path (default `/v1/transactions`) |
| `auth_token` | `str \| None` | No | Bearer token or API key |
| `allowed_hosts` | `tuple[str, ...]`| No | Whitelist of allowed domain names (SSRF protection) |
| `timeout_seconds` | `float` | No | HTTP request timeout (default 30.0s) |
| `max_retries` | `int` | No | Transient network retry attempts (default 3) |

---

## 3. Security & SSRF Protection

To prevent Server-Side Request Forgery attacks, `BankRestConnector` validates all URLs against `allowed_hosts`:
```python
parsed = urlparse(base_url)
if allowed_hosts and parsed.hostname not in allowed_hosts:
    raise SSRFProtectionError(f"Host '{parsed.hostname}' is not in allowed hosts")
```
Attempts to configure connectors pointing to public cloud metadata endpoints (`169.254.169.254`), loopback addresses (`127.0.0.1`), or external hostnames outside the bank whitelist will be rejected immediately upon initialization.

---

## 4. Cursor Resumption & Pagination

`BankRestConnector` supports both cursor-based and offset-based pagination:
- When calling `fetch_batch(context)`, the current cursor is passed as query parameter `?cursor=<cursor>`.
- The bank API is expected to return:
  ```json
  {
    "items": [...],
    "next_cursor": "eyJpZCI6MTAyM30=",
    "has_more": true
  }
  ```
- If the endpoint returns HTTP 429 (Too Many Requests), `BankRestConnector` parses the `Retry-After` header and raises `ConnectorRateLimitError(retry_after=...)` so the ingestion scheduler can back off cleanly.
