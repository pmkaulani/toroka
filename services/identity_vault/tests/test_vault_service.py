"""Tests for the isolated Identity Vault service, envelope encryption, and access boundaries."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient

from toroka_identity_vault.config import VaultSettings
from toroka_identity_vault.crypto import (
    DurableKMSKeyProvider,
    EnvelopeVaultCipher,
    LocalKMSKeyProvider,
)
from toroka_identity_vault.grants import (
    create_signed_reveal_grant,
    verify_signed_reveal_grant,
)
from toroka_identity_vault.main import create_app


@pytest.fixture
def vault_settings():
    return VaultSettings(
        environment="test",
        database_url="sqlite:///:memory:",
        service_token="test-vault-token-12345678901234567890",
        encryption_mode="envelope",
        kms_key_id="alias/test-kms-key",
    )


@pytest.fixture
def vault_app(vault_settings):
    return create_app(vault_settings)


@pytest.fixture
def vault_client(vault_app):
    return TestClient(vault_app)


def test_envelope_encryption_roundtrip():
    kms = LocalKMSKeyProvider()
    cipher = EnvelopeVaultCipher(
        key_provider=kms,
        key_id_map={"v1": "alias/test-key"},
        current_version="v1",
    )

    aad = b"inst-001:STF-01"
    ciphertext, version = cipher.encrypt("John Doe", "v1", aad=aad)
    assert version == "v1"

    decrypted = cipher.decrypt(ciphertext, "v1", aad=aad)
    assert decrypted == "John Doe"


def test_durable_kms_key_provider_roundtrip():
    master_kek = b"01234567890123456789012345678901"  # 32 bytes
    kms = DurableKMSKeyProvider(master_kek=master_kek, key_version="v1")
    cipher = EnvelopeVaultCipher(
        key_provider=kms,
        key_id_map={"v1": "alias/durable-key"},
        current_version="v1",
    )

    aad = b"inst-002:STF-02"
    ciphertext, version = cipher.encrypt("Confidential Employee", "v1", aad=aad)
    decrypted = cipher.decrypt(ciphertext, "v1", aad=aad)
    assert decrypted == "Confidential Employee"


def test_envelope_encryption_fails_on_aad_mismatch():
    kms = LocalKMSKeyProvider()
    cipher = EnvelopeVaultCipher(
        key_provider=kms,
        key_id_map={"v1": "alias/test-key"},
        current_version="v1",
    )

    aad_alice = b"inst-001:STF-ALICE"
    aad_bob = b"inst-001:STF-BOB"

    ciphertext, _ = cipher.encrypt("Alice Real Name", "v1", aad=aad_alice)

    # Attempting to decrypt with Bob's pseudonym or another installation must fail
    with pytest.raises(ValueError, match="Envelope decryption failed"):
        cipher.decrypt(ciphertext, "v1", aad=aad_bob)


def test_vault_internal_service_authentication_required(vault_client):
    # Missing token -> 422 (FastAPI header validation) or 401
    resp = vault_client.post(
        "/internal/v1/reveals/consume",
        json={
            "installation_id": "inst-1",
            "pseudonym": "P-1",
            "request_id": "req-1",
            "requester_subject": "inv.alice",
        },
    )
    assert resp.status_code in (401, 422)

    # Invalid token -> 401
    resp2 = vault_client.post(
        "/internal/v1/reveals/consume",
        headers={"X-Internal-Service-Token": "wrong-token"},
        json={
            "installation_id": "inst-1",
            "pseudonym": "P-1",
            "request_id": "req-1",
            "requester_subject": "inv.alice",
        },
    )
    assert resp2.status_code == 401


def test_vault_store_and_consume_end_to_end(vault_client):
    headers = {"X-Internal-Service-Token": "test-vault-token-12345678901234567890"}

    # 1. Store identity mapping
    store_resp = vault_client.post(
        "/internal/v1/identities",
        headers=headers,
        json={
            "installation_id": "bank-prod-01",
            "pseudonym": "PSEUDO-STAFF-123",
            "plaintext_identity": "Jane Investigator",
            "key_version": "v1",
        },
    )
    assert store_resp.status_code == 201
    assert store_resp.json()["status"] == "stored"

    # Attempt to consume without signed approval token -> 403
    unauthorized_resp = vault_client.post(
        "/internal/v1/reveals/consume",
        headers=headers,
        json={
            "installation_id": "bank-prod-01",
            "pseudonym": "PSEUDO-STAFF-123",
            "request_id": "rev-req-001",
            "requester_subject": "inv.alice",
        },
    )
    assert unauthorized_resp.status_code == 403
    assert "signed approval grant is required" in unauthorized_resp.json()["detail"]

    # 2. Generate valid cryptographic approval grant
    exp = datetime.now(timezone.utc) + timedelta(hours=1)
    valid_token = create_signed_reveal_grant(
        grant_id="rev-req-001",
        installation_id="bank-prod-01",
        case_id="case-100",
        requester_subject="inv.alice",
        approver_subject="auth.charlie",
        pseudonym="PSEUDO-STAFF-123",
        expires_at=exp,
    )

    # Consume identity mapping with signed grant
    consume_resp = vault_client.post(
        "/internal/v1/reveals/consume",
        headers=headers,
        json={
            "installation_id": "bank-prod-01",
            "pseudonym": "PSEUDO-STAFF-123",
            "request_id": "rev-req-001",
            "requester_subject": "inv.alice",
            "reveal_token": valid_token,
        },
    )
    assert consume_resp.status_code == 200
    assert consume_resp.json()["plaintext_identity"] == "Jane Investigator"

    # 3. Re-consumption of same grant is rejected (atomic single-use)
    reconsume_resp = vault_client.post(
        "/internal/v1/reveals/consume",
        headers=headers,
        json={
            "installation_id": "bank-prod-01",
            "pseudonym": "PSEUDO-STAFF-123",
            "request_id": "rev-req-001",
            "requester_subject": "inv.alice",
            "reveal_token": valid_token,
        },
    )
    assert reconsume_resp.status_code == 403
    assert "already been consumed" in reconsume_resp.json()["detail"]


def test_vault_reveal_rejects_scope_mismatch_and_expiry(vault_client):
    headers = {"X-Internal-Service-Token": "test-vault-token-12345678901234567890"}

    # Store identity
    vault_client.post(
        "/internal/v1/identities",
        headers=headers,
        json={
            "installation_id": "bank-prod-01",
            "pseudonym": "TARGET-01",
            "plaintext_identity": "Secret Officer",
            "key_version": "v1",
        },
    )

    now = datetime.now(timezone.utc)
    # Expired token
    expired_token = create_signed_reveal_grant(
        grant_id="req-exp",
        installation_id="bank-prod-01",
        case_id="case-100",
        requester_subject="inv.alice",
        approver_subject="auth.charlie",
        pseudonym="TARGET-01",
        expires_at=now - timedelta(minutes=5),
    )
    exp_resp = vault_client.post(
        "/internal/v1/reveals/consume",
        headers=headers,
        json={
            "installation_id": "bank-prod-01",
            "pseudonym": "TARGET-01",
            "request_id": "req-exp",
            "requester_subject": "inv.alice",
            "reveal_token": expired_token,
        },
    )
    assert exp_resp.status_code == 403
    assert "expired" in exp_resp.json()["detail"]

    # Wrong installation scope
    valid_token = create_signed_reveal_grant(
        grant_id="req-wrong-inst",
        installation_id="bank-prod-01",
        case_id="case-100",
        requester_subject="inv.alice",
        approver_subject="auth.charlie",
        pseudonym="TARGET-01",
        expires_at=now + timedelta(hours=1),
    )
    wrong_inst_resp = vault_client.post(
        "/internal/v1/reveals/consume",
        headers=headers,
        json={
            "installation_id": "bank-other-99",
            "pseudonym": "TARGET-01",
            "request_id": "req-wrong-inst",
            "requester_subject": "inv.alice",
            "reveal_token": valid_token,
        },
    )
    assert wrong_inst_resp.status_code == 403
    assert "scope mismatch" in wrong_inst_resp.json()["detail"]

    # Wrong requester
    wrong_req_resp = vault_client.post(
        "/internal/v1/reveals/consume",
        headers=headers,
        json={
            "installation_id": "bank-prod-01",
            "pseudonym": "TARGET-01",
            "request_id": "req-wrong-inst",
            "requester_subject": "inv.attacker",
            "reveal_token": valid_token,
        },
    )
    assert wrong_req_resp.status_code == 403
    assert "requester scope mismatch" in wrong_req_resp.json()["detail"]


def test_production_startup_refuses_localkms():
    prod_settings = VaultSettings(
        environment="production",
        database_url="postgresql://user:pass@localhost:5432/vault",
        service_token="test-vault-token-12345678901234567890-strong",
        encryption_mode="envelope",
        kms_key_id="alias/prod-key",
        master_kek="",  # empty master key must fail startup
    )
    with pytest.raises(RuntimeError, match="Ephemeral LocalKMS keys are refused in production"):
        prod_settings.validate()


def test_vault_health_endpoints(vault_client):
    r1 = vault_client.get("/internal/v1/health/live")
    assert r1.status_code == 200
    assert r1.json()["status"] == "alive"

    r2 = vault_client.get("/internal/v1/health/ready")
    assert r2.status_code == 200
    assert r2.json()["status"] == "ready"
