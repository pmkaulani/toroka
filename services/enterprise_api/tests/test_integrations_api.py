"""API and end-to-end integration tests for bank connectors, sync jobs, event webhooks, and reconciliation."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
import time
from decimal import Decimal
import httpx
import pytest

from toroka_enterprise.integrations.base import ConnectorBatch, ConnectorContext
from toroka_enterprise.integrations.connectors.events import BankEventConnector
from toroka_enterprise.integrations.connectors.rest import BankRestConnector
from toroka_enterprise.integrations.contracts import (
    CanonicalTransactionRecord,
    Provenance,
    SourceSystem,
)
from toroka_enterprise.integrations.registry import DEFAULT_CONNECTOR_REGISTRY


class MockBankingConnector:
    """Mock connector for testing ingestion jobs and idempotency."""

    def __init__(self, connector_id: str = "cbs-test-01"):
        self.connector_id = connector_id
        self.connector_type = "rest_api"
        self.source_system = SourceSystem.CORE_BANKING
        self.version = "1.0.0"
        self.metadata = {"name": "Test Core Banking API"}
        self.capabilities = {"batch_pagination": True}
        self.call_count = 0
        self.items_to_return: list[CanonicalTransactionRecord] = []

    async def healthcheck(self) -> bool:
        return True

    async def fetch_batch(self, context: ConnectorContext) -> ConnectorBatch:
        self.call_count += 1
        return ConnectorBatch(
            records=self.items_to_return,
            next_cursor="cursor-end",
            has_more=False,
            records_read=len(self.items_to_return),
        )

    async def fetch_events(self, context: ConnectorContext) -> list:
        return []

    async def close(self) -> None:
        pass


@pytest.fixture
def mock_cbs_connector():
    conn = MockBankingConnector("cbs-test-01")
    prov = Provenance(
        source_system=SourceSystem.CORE_BANKING,
        connector_id="cbs-test-01",
        source_record_id="TXN-API-101",
        source_event_timestamp=datetime.now(timezone.utc),
    )
    conn.items_to_return = [
        CanonicalTransactionRecord(
            installation_id="toroka-default-installation",
            record_id="TXN-API-101",
            provenance=prov,
            account_ref="ACC-1111",
            counterparty_ref="ACC-2222",
            amount=Decimal("350000.00"),
            currency="KES",
            direction="DEBIT",
            transaction_type="POSTING",
            narrative="Branch Cash Balancing",
            posting_staff_ref="STF-CASH-01",
        )
    ]
    DEFAULT_CONNECTOR_REGISTRY.register("toroka-default-installation", conn, enabled=True)
    yield conn
    DEFAULT_CONNECTOR_REGISTRY.unregister("toroka-default-installation", "cbs-test-01")


def test_list_and_health_connectors(oidc_client, token_factory, mock_cbs_connector):
    admin_token = token_factory(sub="admin.user", roles=["BANK_SYSADMIN"])
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. List connectors
    resp = oidc_client.get("/api/enterprise/v1/integrations/connectors", headers=headers)
    assert resp.status_code == 200
    connectors = resp.json()
    assert any(c["connector_id"] == "cbs-test-01" for c in connectors)

    # 2. Check health
    health_resp = oidc_client.get(
        "/api/enterprise/v1/integrations/connectors/cbs-test-01/health",
        headers=headers,
    )
    assert health_resp.status_code == 200
    assert health_resp.json()["healthy"] is True


def test_trigger_sync_job_and_idempotency(oidc_client, token_factory, mock_cbs_connector):
    admin_token = token_factory(sub="admin.user", roles=["BANK_SYSADMIN"])
    headers = {"Authorization": f"Bearer {admin_token}"}

    # First Sync
    r1 = oidc_client.post(
        "/api/enterprise/v1/integrations/connectors/cbs-test-01/sync",
        headers=headers,
        json={"batch_size": 100, "max_batches": 2},
    )
    assert r1.status_code == 200
    data1 = r1.json()
    assert data1["status"] == "completed"
    assert data1["records_accepted"] == 1
    assert data1["records_duplicates"] == 0

    # Second Sync with identical record -> Idempotent Duplicate
    r2 = oidc_client.post(
        "/api/enterprise/v1/integrations/connectors/cbs-test-01/sync",
        headers=headers,
        json={"batch_size": 100, "max_batches": 2},
    )
    assert r2.status_code == 200
    data2 = r2.json()
    assert data2["records_accepted"] == 0
    assert data2["records_duplicates"] == 1

    # Third Sync with modified content -> Versioned Correction
    prov = Provenance(
        source_system=SourceSystem.CORE_BANKING,
        connector_id="cbs-test-01",
        source_record_id="TXN-API-101",
        source_event_timestamp=datetime.now(timezone.utc),
    )
    mock_cbs_connector.items_to_return = [
        CanonicalTransactionRecord(
            installation_id="toroka-default-installation",
            record_id="TXN-API-101",
            provenance=prov,
            account_ref="ACC-1111",
            counterparty_ref="ACC-2222",
            amount=Decimal("400000.00"),  # Changed amount
            currency="KES",
            direction="DEBIT",
            transaction_type="POSTING",
            narrative="Corrected Cash Balancing",
            posting_staff_ref="STF-CASH-01",
        )
    ]

    r3 = oidc_client.post(
        "/api/enterprise/v1/integrations/connectors/cbs-test-01/sync",
        headers=headers,
        json={"batch_size": 100, "max_batches": 2},
    )
    assert r3.status_code == 200
    data3 = r3.json()
    assert data3["records_corrected"] == 1


def test_list_integration_jobs_and_reconciliation(oidc_client, token_factory, mock_cbs_connector):
    admin_token = token_factory(sub="admin.user", roles=["BANK_SYSADMIN"])
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Run sync
    oidc_client.post(
        "/api/enterprise/v1/integrations/connectors/cbs-test-01/sync",
        headers=headers,
        json={"batch_size": 100, "max_batches": 1},
    )

    # List jobs
    resp = oidc_client.get("/api/enterprise/v1/integrations/jobs", headers=headers)
    assert resp.status_code == 200
    jobs = resp.json()
    assert len(jobs) >= 1
    assert jobs[0]["connector_id"] == "cbs-test-01"

    # Reconciliation check
    recon_resp = oidc_client.post(
        "/api/enterprise/v1/integrations/reconciliation",
        headers=headers,
        json={
            "connector_id": "cbs-test-01",
            "expected_source_count": 1,
        },
    )
    assert recon_resp.status_code == 200
    recon = recon_resp.json()
    assert recon["status"] == "reconciled"
    assert recon["discrepancy"] == 0


def test_signed_event_webhook_endpoint(oidc_client):
    secret = b"webhook-secret-bank-test-32bytes"
    conn = BankEventConnector(
        connector_id="webhook-cbs-01",
        secret_key=secret,
        timestamp_tolerance_seconds=300,
    )
    DEFAULT_CONNECTOR_REGISTRY.register("toroka-default-installation", conn, enabled=True)

    try:
        payload_data = {
            "event_id": "WEBHOOK-EVT-01",
            "event_type": "POSTING_EVENT",
            "timestamp": int(time.time()),
            "payload": {
                "transaction_id": "TXN-WH-001",
                "timestamp": "2026-11-15 14:00:00",
                "account_number": "ACC-WH-1",
                "amount": "99000.00",
                "direction": "DEBIT",
            },
        }
        raw_body = json.dumps(payload_data).encode("utf-8")
        signature = hmac.new(secret, raw_body, hashlib.sha256).hexdigest()

        # 1. Successful event reception
        r1 = oidc_client.post(
            "/api/enterprise/v1/integrations/events",
            content=raw_body,
            headers={
                "X-Connector-ID": "webhook-cbs-01",
                "X-Signature": signature,
                "Content-Type": "application/json",
            },
        )
        assert r1.status_code == 201
        assert r1.json()["status"] == "processed"

        # 2. Replay of same event -> duplicate acknowledged (idempotent)
        r2 = oidc_client.post(
            "/api/enterprise/v1/integrations/events",
            content=raw_body,
            headers={
                "X-Connector-ID": "webhook-cbs-01",
                "X-Signature": signature,
                "Content-Type": "application/json",
            },
        )
        assert r2.status_code == 200
        assert r2.json()["status"] == "duplicate_acknowledged"

        # 3. Bad signature -> 401
        r3 = oidc_client.post(
            "/api/enterprise/v1/integrations/events",
            content=raw_body,
            headers={
                "X-Connector-ID": "webhook-cbs-01",
                "X-Signature": "invalid-signature",
                "Content-Type": "application/json",
            },
        )
        assert r3.status_code == 401

    finally:
        DEFAULT_CONNECTOR_REGISTRY.unregister("toroka-default-installation", "webhook-cbs-01")


def test_ingestion_quality_and_detector_impact(oidc_client, token_factory, mock_cbs_connector):
    steward_token = token_factory(sub="steward.user", roles=["BANK_DATA_STEWARD"])
    headers = {"Authorization": f"Bearer {steward_token}"}

    resp = oidc_client.get("/api/enterprise/v1/integrations/quality", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "detector_impact" in data
    assert any(d["detector_id"] == "access_justification" for d in data["detector_impact"])
