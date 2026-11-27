"""Security hardening, CORS, audit checkpointing, and production configuration regression tests."""
from __future__ import annotations

import base64
import json
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from toroka_enterprise_api.config import EnterpriseSettings
from toroka_enterprise_api.main import create_app
from toroka_enterprise_api.persistence.audit import append_audit
from toroka_enterprise_api.persistence.checkpoints import (
    AuditCheckpointManager,
    HMACCheckpointSigner,
    HMACCheckpointVerifier,
    MemoryImmutableCheckpointStore,
)
from toroka_enterprise_api.persistence.models import Base, AuditRecord


def test_production_rejects_development_auth():
    settings = EnterpriseSettings(
        environment="production",
        audit_checkpoint_dir="/tmp/toroka-test-checkpoints",
        audit_checkpoint_hmac_key="k" * 32,
        auth_mode="development",
    )
    with pytest.raises(RuntimeError):
        settings.validate()


def test_production_rejects_raw_vault_key():
    settings = EnterpriseSettings(
        environment="production",
        audit_checkpoint_dir="/tmp/toroka-test-checkpoints",
        audit_checkpoint_hmac_key="k" * 32,
        auth_mode="oidc",
        oidc_issuer="https://idp.example.com",
        oidc_audience="toroka-enterprise",
        oidc_jwks_url="https://idp.example.com/jwks",
        database_url="postgresql+psycopg://user:pass@db/enterprise",
        vault_service_url="https://vault.internal",
        vault_key="development-only-raw-fernet-key",
        expected_schema_revision="expected-revision",
    )
    with pytest.raises(RuntimeError, match="raw Fernet key"):
        settings.validate()


def test_production_requires_https_cors_origins():
    settings = EnterpriseSettings(
        environment="production",
        audit_checkpoint_dir="/tmp/toroka-test-checkpoints",
        audit_checkpoint_hmac_key="k" * 32,
        auth_mode="oidc",
        oidc_issuer="https://idp.example.com",
        oidc_audience="toroka-enterprise",
        oidc_jwks_url="https://idp.example.com/jwks",
        database_url="postgresql+psycopg://user:pass@db/enterprise",
        vault_service_url="https://vault.internal",
        expected_schema_revision="expected-revision",
        cors_allowed_origins=("http://insecure.bank.com",),
    )
    with pytest.raises(RuntimeError, match="HTTPS"):
        settings.validate()


def test_production_requires_vault_service_url():
    settings = EnterpriseSettings(
        environment="production",
        audit_checkpoint_dir="/tmp/toroka-test-checkpoints",
        audit_checkpoint_hmac_key="k" * 32,
        auth_mode="oidc",
        oidc_issuer="https://idp.example.com",
        oidc_audience="toroka-enterprise",
        oidc_jwks_url="https://idp.example.com/jwks",
        database_url="postgresql+psycopg://user:pass@db/enterprise",
        vault_service_url="",
        expected_schema_revision="expected-revision",
    )
    with pytest.raises(RuntimeError, match="Identity Vault service"):
        settings.validate()


def test_production_requires_expected_schema_revision():
    settings = EnterpriseSettings(
        environment="production",
        audit_checkpoint_dir="/tmp/toroka-test-checkpoints",
        audit_checkpoint_hmac_key="k" * 32,
        auth_mode="oidc",
        oidc_issuer="https://idp.example.com",
        oidc_audience="toroka-enterprise",
        oidc_jwks_url="https://idp.example.com/jwks",
        database_url="postgresql+psycopg://user:pass@db/enterprise",
        vault_service_url="https://vault.internal",
        expected_schema_revision="",
    )
    with pytest.raises(RuntimeError, match="schema revision is required"):
        settings.validate()


def test_production_requires_postgresql():
    settings = EnterpriseSettings(
        environment="production",
        audit_checkpoint_dir="/tmp/toroka-test-checkpoints",
        audit_checkpoint_hmac_key="k" * 32,
        auth_mode="oidc",
        oidc_issuer="https://idp.example.com",
        oidc_audience="toroka-enterprise",
        oidc_jwks_url="https://idp.example.com/jwks",
        database_url="sqlite:///./enterprise_operational.db",
        vault_service_url="https://vault.internal",
        expected_schema_revision="rev-001",
    )
    with pytest.raises(RuntimeError, match="requires PostgreSQL"):
        settings.validate()


def test_security_headers_and_csp(dev_client):
    resp = dev_client.get("/health/live")
    assert resp.status_code == 200

    # Strict security headers
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["Referrer-Policy"] == "no-referrer"
    assert resp.headers["Cache-Control"] == "no-store"
    assert resp.headers["X-Frame-Options"] == "DENY"

    # CSP header
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp


def test_correlation_id_validation_and_sanitization(dev_client):
    # Valid alphanumeric correlation ID is preserved
    resp = dev_client.get("/health/live", headers={"X-Correlation-ID": "CORR-REQ-123_456"})
    assert resp.headers["X-Correlation-ID"] == "CORR-REQ-123_456"

    # Invalid / dangerous correlation ID with special characters is sanitized to fresh UUID
    resp2 = dev_client.get("/health/live", headers={"X-Correlation-ID": "bad<script>id\n\r"})
    assert resp2.headers["X-Correlation-ID"] != "bad<script>id\n\r"
    assert len(resp2.headers["X-Correlation-ID"]) >= 16


def test_payload_too_large_rejection(dev_client):
    # Over 10MB Content-Length is rejected with 413
    resp = dev_client.post(
        "/api/enterprise/v1/cases/intake",
        headers={"Content-Length": str(20 * 1024 * 1024)},
    )
    assert resp.status_code == 413
    assert resp.json()["error"] == "payload_too_large"


def test_rate_limiting_on_sensitive_consume(dev_client, monkeypatch):
    # Rapid successive requests to reveal consume trigger 429
    url = "/api/enterprise/v1/reveal-requests/fake-id/consume"
    responses = []
    for _ in range(25):
        r = dev_client.post(url, headers={"X-Dev-User": "investigator.alice"})
        responses.append(r.status_code)

    assert 429 in responses


def test_audit_checkpoint_signing_and_verification():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)

    signing_key = b"bank-secure-audit-signing-key-32b"
    signer = HMACCheckpointSigner(signing_key, key_id="bank-kms-key-v1")
    verifier = HMACCheckpointVerifier(signing_key, key_id="bank-kms-key-v1")
    store = MemoryImmutableCheckpointStore()

    with Session(engine) as db:
        # Append two audit records
        append_audit(
            db,
            installation_id="bank-pilot-01",
            actor_subject="inv.alice",
            actor_role="investigator",
            action="case_created",
            target_type="case",
            target_id="case-101",
            safe_metadata={"case_id": "case-101"},
        )
        append_audit(
            db,
            installation_id="bank-pilot-01",
            actor_subject="auth.charlie",
            actor_role="authoriser",
            action="reveal_approved",
            target_type="reveal_request",
            target_id="rev-202",
            safe_metadata={"case_id": "case-101"},
        )
        db.commit()

        # Create signed checkpoint
        checkpoint = AuditCheckpointManager.create_checkpoint(
            installation_id="bank-pilot-01",
            db=db,
            signer=signer,
            store=store,
        )

        assert checkpoint["data"]["head_sequence"] == 2
        assert checkpoint["key_id"] == "bank-kms-key-v1"

        # Verify against intact database
        valid, msg = AuditCheckpointManager.verify_checkpoint(checkpoint, verifier, db)
        assert valid is True
        assert "successfully verified" in msg

        # Attempt to overwrite same checkpoint in store must fail (immutability)
        with pytest.raises(FileExistsError):
            AuditCheckpointManager.create_checkpoint(
                installation_id="bank-pilot-01",
                db=db,
                signer=signer,
                store=store,
            )

        # Tampering test: modify an audit record in the database
        rec = db.query(AuditRecord).filter_by(sequence=2).first()
        rec.event_hash = "tampered_fake_hash_value"
        db.commit()

        # Verification must now fail!
        valid_tampered, msg_tampered = AuditCheckpointManager.verify_checkpoint(checkpoint, verifier, db)
        assert valid_tampered is False
        assert "tampering detected" in msg_tampered


def test_production_requires_strong_vault_service_token():
    settings = EnterpriseSettings(
        environment="production",
        audit_checkpoint_dir="/tmp/toroka-test-checkpoints",
        audit_checkpoint_hmac_key="k" * 32,
        auth_mode="oidc",
        oidc_issuer="https://idp.example.com",
        oidc_audience="toroka-enterprise",
        oidc_jwks_url="https://idp.example.com/jwks",
        database_url="postgresql+psycopg://user:pass@db/enterprise",
        vault_service_url="https://vault.internal",
        vault_service_token="short-token",
        expected_schema_revision="rev-001",
    )
    with pytest.raises(RuntimeError, match="at least 32 characters"):
        settings.validate()


def test_production_rejects_sample_federation_salt(monkeypatch):
    monkeypatch.setenv("TOROKA_FEDERATED_MULE_SALT", "TOROKA_CONSORTIUM_MULE_SALT_KENYA_CBK_2026_V1")
    settings = EnterpriseSettings(
        environment="production",
        audit_checkpoint_dir="/tmp/toroka-test-checkpoints",
        audit_checkpoint_hmac_key="k" * 32,
        auth_mode="oidc",
        oidc_issuer="https://idp.example.com",
        oidc_audience="toroka-enterprise",
        oidc_jwks_url="https://idp.example.com/jwks",
        database_url="postgresql+psycopg://user:pass@db/enterprise",
        vault_service_url="https://vault.internal",
        vault_service_token="a" * 32,
        expected_schema_revision="rev-001",
    )
    with pytest.raises(RuntimeError, match="default sample federation salt"):
        settings.validate()


def test_vault_production_validations():
    from toroka_identity_vault.config import VaultSettings

    # 1. Rejects short service token
    v1 = VaultSettings(
        environment="production",
        database_url="postgresql+psycopg://user:pass@db/vault",
        service_token="short",
        master_kek="a" * 32,
    )
    with pytest.raises(RuntimeError, match="at least 32 characters"):
        v1.validate()

    # 2. Rejects raw Fernet key
    v2 = VaultSettings(
        environment="production",
        database_url="postgresql+psycopg://user:pass@db/vault",
        service_token="a" * 32,
        master_kek="a" * 32,
        vault_key="raw-fernet-key",
    )
    with pytest.raises(RuntimeError, match="must not use raw Fernet key"):
        v2.validate()

    # 3. Rejects missing master_kek / LocalKMS
    v3 = VaultSettings(
        environment="production",
        database_url="postgresql+psycopg://user:pass@db/vault",
        service_token="a" * 32,
        master_kek="",
    )
    with pytest.raises(RuntimeError, match="durable KMS master key"):
        v3.validate()


def test_integration_cursor_lease_concurrency_and_expiry():
    from datetime import datetime, timezone, timedelta
    from toroka_enterprise.integrations.models import IntegrationBase, IntegrationCursor
    from toroka_enterprise.integrations.ingestion import acquire_cursor_lease, release_cursor_lease

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    IntegrationBase.metadata.create_all(engine)

    with Session(engine) as db:
        inst_id = "inst-pilot-01"
        conn_id = "core-banking-feed"
        worker_a = "worker-node-a"
        worker_b = "worker-node-b"

        # 1. Worker A acquires lease
        acquired_a = acquire_cursor_lease(db, installation_id=inst_id, connector_id=conn_id, worker_id=worker_a, lease_seconds=60)
        assert acquired_a is True
        db.commit()

        # 2. Worker B attempts to acquire while active -> blocked
        acquired_b = acquire_cursor_lease(db, installation_id=inst_id, connector_id=conn_id, worker_id=worker_b, lease_seconds=60)
        assert acquired_b is False
        db.rollback()

        # 3. Worker A releases lease
        release_cursor_lease(db, installation_id=inst_id, connector_id=conn_id, worker_id=worker_a)
        db.commit()

        # 4. Worker B acquires successfully after release
        acquired_b_after = acquire_cursor_lease(db, installation_id=inst_id, connector_id=conn_id, worker_id=worker_b, lease_seconds=60)
        assert acquired_b_after is True
        db.commit()

        # 5. Simulate crash recovery: lease expires in the past
        cursor = db.query(IntegrationCursor).filter_by(installation_id=inst_id, connector_id=conn_id).one()
        cursor.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
        db.commit()

        # 6. Worker A can steal / acquire expired lease
        acquired_a_expired = acquire_cursor_lease(db, installation_id=inst_id, connector_id=conn_id, worker_id=worker_a, lease_seconds=60)
        assert acquired_a_expired is True
        db.commit()

        # 6. Worker A can steal / acquire expired lease
        acquired_a_expired = acquire_cursor_lease(db, installation_id=inst_id, connector_id=conn_id, worker_id=worker_a, lease_seconds=60)
        assert acquired_a_expired is True
        db.commit()

