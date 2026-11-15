"""Tests for OIDC authentication, JWKS validation, claim resolution, and role enforcement."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


def test_01_successful_authentication(oidc_client, token_factory):
    token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])
    resp = oidc_client.get(
        "/api/enterprise/v1/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["subject"] == "investigator.alice"
    assert data["roles"] == ["investigator"]


def test_02_missing_authorization_header(oidc_client):
    resp = oidc_client.get("/api/enterprise/v1/me")
    assert resp.status_code == 401
    assert "Authentication required" in resp.json()["detail"]


def test_03_invalid_signature_rejected(oidc_client, token_factory, secondary_key):
    # Signed with secondary_key, but header claims kid="key-primary"
    token = token_factory(
        key=secondary_key,
        kid="key-primary",
        roles=["BANK_INVESTIGATOR"],
    )
    resp = oidc_client.get(
        "/api/enterprise/v1/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401
    assert "Invalid or expired access token" in resp.json()["detail"]


def test_04_expired_token_rejected(oidc_client, token_factory):
    token = token_factory(
        exp_offset=-60,
        iat_offset=-120,
        roles=["BANK_INVESTIGATOR"],
    )
    resp = oidc_client.get(
        "/api/enterprise/v1/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401
    assert "Invalid or expired access token" in resp.json()["detail"]


def test_05_wrong_issuer_rejected(oidc_client, token_factory):
    token = token_factory(
        iss="https://malicious-idp.example.com",
        roles=["BANK_INVESTIGATOR"],
    )
    resp = oidc_client.get(
        "/api/enterprise/v1/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401
    assert "Invalid or expired access token" in resp.json()["detail"]


def test_06_wrong_audience_rejected(oidc_client, token_factory):
    token = token_factory(
        aud="wrong-audience-api",
        roles=["BANK_INVESTIGATOR"],
    )
    resp = oidc_client.get(
        "/api/enterprise/v1/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401
    assert "Invalid or expired access token" in resp.json()["detail"]


def test_07_missing_subject_rejected(oidc_client, token_factory):
    token = token_factory(
        sub="   ",
        roles=["BANK_INVESTIGATOR"],
    )
    resp = oidc_client.get(
        "/api/enterprise/v1/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401
    assert "Invalid identity subject" in resp.json()["detail"]


def test_08_missing_role_claims_rejected(oidc_client, token_factory):
    token = token_factory(roles=[])
    resp = oidc_client.get(
        "/api/enterprise/v1/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403
    assert "No recognised Enterprise role is assigned" in resp.json()["detail"]


def test_09_unknown_external_role_denied(oidc_client, token_factory):
    token = token_factory(roles=["BANK_TELLER_GENERAL", "UNRECOGNISED_GROUP"])
    resp = oidc_client.get(
        "/api/enterprise/v1/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403
    assert "No recognised Enterprise role is assigned" in resp.json()["detail"]


def test_10_multiple_valid_role_claims(oidc_client, token_factory):
    token = token_factory(
        sub="dual.officer",
        roles=["BANK_INVESTIGATOR", "BANK_AUTHORISER"],
    )
    resp = oidc_client.get(
        "/api/enterprise/v1/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["roles"] == ["authoriser", "investigator"]


def test_11_correct_permission_enforcement(oidc_client, token_factory):
    # Capability route requires a valid bank role
    token = token_factory(roles=["BANK_AUDITOR"])
    resp = oidc_client.get(
        "/api/enterprise/v1/capabilities",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["service"] == "toroka-enterprise"


def test_12_permission_enforcement_rejects_unprivileged_role(oidc_app, token_factory):
    from fastapi import APIRouter, Depends
    from toroka_enterprise_api.auth import require_roles

    test_router = APIRouter()

    @test_router.get(
        "/test/investigators-only",
        dependencies=[Depends(require_roles("investigator"))],
    )
    def inv_only():
        return {"ok": True}

    oidc_app.include_router(test_router)
    client = TestClient(oidc_app, client=("127.0.0.1", 50000))

    # Auditor token attempting to access investigator-only route
    token = token_factory(roles=["BANK_AUDITOR"])
    resp = client.get(
        "/test/investigators-only",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403
    assert "You do not have permission to perform this action" in resp.json()["detail"]


def test_13_jwks_key_rotation(oidc_app, oidc_client, token_factory, secondary_key, secondary_jwk_dict):
    # Dynamically rotate keys: add secondary key to JWKS
    oidc_app.state.jwks_client.add_key(secondary_jwk_dict)

    rotated_token = token_factory(
        key=secondary_key,
        kid="key-secondary",
        roles=["BANK_INVESTIGATOR"],
    )
    resp = oidc_client.get(
        "/api/enterprise/v1/me",
        headers={"Authorization": f"Bearer {rotated_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["subject"] == "investigator.alice"


def test_14_jwks_retrieval_failure_returns_503(oidc_app, oidc_client, token_factory):
    oidc_app.state.jwks_client.simulate_connection_failure = True
    token = token_factory(roles=["BANK_INVESTIGATOR"])
    resp = oidc_client.get(
        "/api/enterprise/v1/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 503
    assert "Identity provider verification is temporarily unavailable" in resp.json()["detail"]
