"""Tests for bank connector implementations (REST, File, Database, Signed Events)."""
from __future__ import annotations

import csv
import hashlib
import hmac
import json
import time
from decimal import Decimal
import httpx
import pytest
from sqlalchemy import create_engine, text

from toroka_enterprise.integrations.base import ConnectorContext
from toroka_enterprise.integrations.connectors.database import BankDatabaseConnector
from toroka_enterprise.integrations.connectors.events import BankEventConnector
from toroka_enterprise.integrations.connectors.file import BankFileConnector, compute_file_hash
from toroka_enterprise.integrations.connectors.rest import BankRestConnector
from toroka_enterprise.integrations.contracts import SourceSystem
from toroka_enterprise.integrations.exceptions import (
    ConnectorAuthenticationError,
    ConnectorRateLimitError,
    ReplayError,
    SSRFProtectionError,
    SchemaValidationError,
)


@pytest.mark.anyio
async def test_rest_connector_fetch_and_pagination():
    def handler(request: httpx.Request) -> httpx.Response:
        cursor = request.url.params.get("cursor")
        if cursor == "page-2":
            return httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "transaction_id": "TXN-2001",
                            "timestamp": "2026-11-15T11:00:00Z",
                            "account_number": "ACC-2",
                            "amount": "2000.00",
                            "direction": "CREDIT",
                        }
                    ],
                    "next_cursor": None,
                    "has_more": False,
                },
            )
        return httpx.Response(
            200,
            json={
                "items": [
                    {
                        "transaction_id": "TXN-1001",
                        "timestamp": "2026-11-15T10:00:00Z",
                        "account_number": "ACC-1",
                        "amount": "1000.00",
                        "direction": "DEBIT",
                    }
                ],
                "next_cursor": "page-2",
                "has_more": True,
            },
        )

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)

    connector = BankRestConnector(
        connector_id="mock-rest-01",
        base_url="https://api.bank.internal",
        client=client,
        allowed_hosts=("api.bank.internal",),
    )

    ctx1 = ConnectorContext(installation_id="inst-1", connector_id="mock-rest-01", cursor=None)
    batch1 = await connector.fetch_batch(ctx1)
    assert len(batch1.records) == 1
    assert batch1.records[0].record_id == "TXN-1001"
    assert batch1.next_cursor == "page-2"
    assert batch1.has_more is True

    ctx2 = ConnectorContext(installation_id="inst-1", connector_id="mock-rest-01", cursor="page-2")
    batch2 = await connector.fetch_batch(ctx2)
    assert len(batch2.records) == 1
    assert batch2.records[0].record_id == "TXN-2001"
    assert batch2.has_more is False

    await connector.close()


@pytest.mark.anyio
async def test_rest_connector_auth_and_rate_limit_errors():
    def auth_err_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "unauthorized"})

    client_auth = httpx.AsyncClient(transport=httpx.MockTransport(auth_err_handler))
    conn_auth = BankRestConnector(
        connector_id="auth-fail",
        base_url="https://api.bank.internal",
        client=client_auth,
    )
    with pytest.raises(ConnectorAuthenticationError):
        await conn_auth.fetch_batch(ConnectorContext(installation_id="i", connector_id="c"))
    await conn_auth.close()

    def rate_limit_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"error": "too many requests"})

    client_rate = httpx.AsyncClient(transport=httpx.MockTransport(rate_limit_handler))
    conn_rate = BankRestConnector(
        connector_id="rate-fail",
        base_url="https://api.bank.internal",
        client=client_rate,
    )
    with pytest.raises(ConnectorRateLimitError):
        await conn_rate.fetch_batch(ConnectorContext(installation_id="i", connector_id="c"))
    await conn_rate.close()


def test_rest_connector_ssrf_protection():
    with pytest.raises(SSRFProtectionError, match="not in allowed hosts"):
        BankRestConnector(
            connector_id="ssrf-test",
            base_url="https://malicious.external.com",
            allowed_hosts=("trusted.bank.internal",),
        )


@pytest.mark.anyio
async def test_file_connector_csv_and_checksum(tmp_path):
    f1 = tmp_path / "trans_20261115_01.csv"
    with f1.open("w", newline="", encoding="utf-8") as fp:
        writer = csv.writer(fp)
        writer.writerow(["transaction_id", "timestamp", "account_number", "amount", "direction"])
        writer.writerow(["F-TXN-01", "2026-11-15 08:00:00", "ACC-FILE-1", "50000.00", "DEBIT"])
        writer.writerow(["F-TXN-02", "2026-11-15 08:30:00", "ACC-FILE-2", "75000.00", "CREDIT"])

    checksum = compute_file_hash(f1)
    assert len(checksum) == 64

    conn = BankFileConnector(
        connector_id="file-csv-01",
        input_directory=tmp_path,
        file_pattern="*.csv",
        format="csv",
    )

    is_healthy = await conn.healthcheck()
    assert is_healthy is True

    batch = await conn.fetch_batch(ConnectorContext(installation_id="inst-1", connector_id="file-csv-01"))
    assert len(batch.records) == 2
    assert batch.records[0].record_id == "F-TXN-01"
    assert batch.records[1].amount == Decimal("75000.00")
    assert batch.next_cursor == "trans_20261115_01.csv"
    assert batch.has_more is False


@pytest.mark.anyio
async def test_database_connector_query_and_allowlist():
    engine = create_engine("sqlite:///:memory:")
    with engine.connect() as conn:
        conn.execute(text("CREATE TABLE vw_core_transactions (id INT, transaction_id TEXT, timestamp TEXT, account_number TEXT, amount TEXT, direction TEXT)"))
        conn.execute(text("INSERT INTO vw_core_transactions VALUES (1, 'DB-TXN-01', '2026-11-15 09:00:00', 'ACC-DB-1', '12000.00', 'DEBIT')"))
        conn.execute(text("INSERT INTO vw_core_transactions VALUES (2, 'DB-TXN-02', '2026-11-15 09:30:00', 'ACC-DB-2', '18000.00', 'CREDIT')"))
        conn.commit()

    conn = BankDatabaseConnector(
        connector_id="db-cbs-01",
        engine=engine,
        view_name="vw_core_transactions",
        cursor_column="id",
        allowed_views=("vw_core_transactions",),
    )

    assert await conn.healthcheck() is True

    batch = await conn.fetch_batch(ConnectorContext(installation_id="inst-1", connector_id="db-cbs-01", batch_size=10))
    assert len(batch.records) == 2
    assert batch.records[0].record_id == "DB-TXN-01"
    assert batch.next_cursor == "2"

    # Disallowed view check
    with pytest.raises(SchemaValidationError, match="not in the allowed views"):
        BankDatabaseConnector(
            connector_id="db-bad",
            engine=engine,
            view_name="unauthorized_private_table",
            allowed_views=("vw_core_transactions",),
        )

    # Disallowed cursor column check (SQL injection guard)
    with pytest.raises(SchemaValidationError, match="Invalid cursor column"):
        BankDatabaseConnector(
            connector_id="db-bad-col",
            engine=engine,
            view_name="vw_core_transactions",
            cursor_column="id; DROP TABLE users; --",
            allowed_views=("vw_core_transactions",),
        )


def test_signed_event_connector_hmac_and_replay():
    secret = b"bank-super-secure-event-secret-32b"
    conn = BankEventConnector(
        connector_id="cbs-events-01",
        secret_key=secret,
        timestamp_tolerance_seconds=300,
    )

    payload_dict = {
        "event_id": "EVT-9001",
        "event_type": "CBS_JOURNAL_POSTED",
        "timestamp": int(time.time()),
        "payload": {
            "transaction_id": "EVT-TXN-01",
            "timestamp": "2026-11-15 12:00:00",
            "account_number": "ACC-EVT-1",
            "amount": "450000.00",
            "direction": "DEBIT",
        },
    }
    raw_body = json.dumps(payload_dict).encode("utf-8")
    signature = hmac.new(secret, raw_body, hashlib.sha256).hexdigest()

    event_id, event_type, record = conn.verify_and_parse_event(raw_body, signature, "inst-1")
    assert event_id == "EVT-9001"
    assert event_type == "CBS_JOURNAL_POSTED"
    assert record.record_id == "EVT-TXN-01"

    # Bad signature
    with pytest.raises(ReplayError, match="Invalid HMAC"):
        conn.verify_and_parse_event(raw_body, "wrong_signature_hex", "inst-1")

    # Expired timestamp (replay attack simulation)
    old_payload = dict(payload_dict)
    old_payload["timestamp"] = int(time.time()) - 600  # 10 minutes ago
    old_body = json.dumps(old_payload).encode("utf-8")
    old_sig = hmac.new(secret, old_body, hashlib.sha256).hexdigest()
    with pytest.raises(ReplayError, match="expired or clock skewed"):
        conn.verify_and_parse_event(old_body, old_sig, "inst-1")
