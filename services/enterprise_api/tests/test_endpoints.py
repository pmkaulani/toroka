"""Tests for Enterprise API endpoints, data contract exposure, and security headers."""
from __future__ import annotations

from fastapi.testclient import TestClient
from toroka_enterprise.data_contract import (
    CONTRACT_VERSION,
    DETECTOR_DEPENDENCIES,
    contract_fingerprint,
)

from toroka_enterprise_api.config import EnterpriseSettings
from toroka_enterprise_api.main import create_app


def test_18_data_contract_requires_authentication(oidc_client):
    resp = oidc_client.get("/api/enterprise/v1/data-contract")
    assert resp.status_code == 401


def test_19_data_contract_returns_actual_phase2_fingerprint(oidc_client, token_factory):
    token = token_factory(roles=["BANK_INVESTIGATOR"])
    resp = oidc_client.get(
        "/api/enterprise/v1/data-contract",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["version"] == CONTRACT_VERSION
    assert data["version"] == "2.0.0"
    assert data["sha256"] == contract_fingerprint()
    assert data["sha256"] == "3d2fa5df86a37dc1903b55ef3f4318819395842dcc8d901a931f7bed9c769c40"
    assert "feeds" in data["contract"]
    assert "detectors" in data["contract"]
    assert len(data["contract"]["detectors"]) == len(DETECTOR_DEPENDENCIES)


def test_20_detectors_endpoint_returns_actual_registry(oidc_client, token_factory):
    token = token_factory(roles=["BANK_INVESTIGATOR"])
    resp = oidc_client.get(
        "/api/enterprise/v1/detectors",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 8
    assert len(data["detectors"]) == 8

    detector_ids = [d["detector_id"] for d in data["detectors"]]
    assert detector_ids == [
        "access_justification",
        "bulk_unjustified_browsing",
        "auth_channel_change",
        "account_lifecycle",
        "change_then_money",
        "suspense_posting_integrity",
        "payroll_beneficiary_integrity",
        "entitlement_integrity",
    ]


def test_21_health_endpoint_does_not_leak_internal_configuration(oidc_client):
    resp = oidc_client.get("/health/live")
    assert resp.status_code == 200
    data = resp.json()
    assert data == {"status": "alive", "service": "toroka-enterprise-api"}
    # Assert no sensitive keys
    assert "settings" not in data
    assert "database" not in data
    assert "issuer" not in data


def test_22_security_headers_and_correlation_id(oidc_client):
    custom_corr_id = "test-corr-12345"
    resp = oidc_client.get("/health/live", headers={"X-Correlation-ID": custom_corr_id})
    assert resp.status_code == 200
    assert resp.headers["X-Correlation-ID"] == custom_corr_id
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["Referrer-Policy"] == "no-referrer"
    assert resp.headers["Cache-Control"] == "no-store"
    assert resp.headers["X-Frame-Options"] == "DENY"

    # Generated correlation ID when none supplied
    resp2 = oidc_client.get("/health/live")
    assert "X-Correlation-ID" in resp2.headers
    assert len(resp2.headers["X-Correlation-ID"]) > 10


def test_23_production_disables_documentation_routes():
    from cryptography.fernet import Fernet
    prod_settings = EnterpriseSettings(
        environment="production",
        auth_mode="oidc",
        oidc_issuer="https://idp.bank.local",
        oidc_audience="toroka-enterprise",
        oidc_jwks_url="https://idp.bank.local/.well-known/jwks.json",
        database_url="postgresql+psycopg://db.bank.local/toroka",
        vault_database_url="postgresql+psycopg://vault.bank.local/toroka_vault",
        vault_key=Fernet.generate_key().decode(),
    )
    prod_app = create_app(prod_settings)
    client = TestClient(prod_app, client=("127.0.0.1", 50000))

    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404
