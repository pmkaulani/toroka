"""Tests for the isolated Identity Vault service, envelope encryption, and access boundaries."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from toroka_identity_vault.config import VaultSettings
from toroka_identity_vault.crypto import (
    EnvelopeVaultCipher,
    LocalKMSKeyProvider,
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

    # 2. Consume identity mapping with correct installation
    consume_resp = vault_client.post(
        "/internal/v1/reveals/consume",
        headers=headers,
        json={
            "installation_id": "bank-prod-01",
            "pseudonym": "PSEUDO-STAFF-123",
            "request_id": "rev-req-001",
            "requester_subject": "inv.alice",
        },
    )
    assert consume_resp.status_code == 200
    assert consume_resp.json()["plaintext_identity"] == "Jane Investigator"

    # 3. Attempt consume with mismatched installation scope -> 404
    cross_resp = vault_client.post(
        "/internal/v1/reveals/consume",
        headers=headers,
        json={
            "installation_id": "different-bank-02",
            "pseudonym": "PSEUDO-STAFF-123",
            "request_id": "rev-req-002",
            "requester_subject": "inv.attacker",
        },
    )
    assert cross_resp.status_code == 404


def test_vault_health_endpoints(vault_client):
    r1 = vault_client.get("/internal/v1/health/live")
    assert r1.status_code == 200
    assert r1.json()["status"] == "alive"

    r2 = vault_client.get("/internal/v1/health/ready")
    assert r2.status_code == 200
    assert r2.json()["status"] == "ready"
