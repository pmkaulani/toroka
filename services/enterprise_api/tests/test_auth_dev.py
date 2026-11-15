"""Tests for local development authentication adapter and safety constraints."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from toroka_enterprise_api.config import EnterpriseSettings
from toroka_enterprise_api.main import create_app


def test_15_development_authentication_works_on_loopback(dev_client):
    resp = dev_client.get(
        "/api/enterprise/v1/me",
        headers={
            "X-Dev-User": "local.dev.investigator",
            "X-Dev-Roles": "investigator,authoriser",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["subject"] == "local.dev.investigator"
    assert data["roles"] == ["authoriser", "investigator"]


def test_15b_development_authentication_requires_identity(dev_client):
    resp = dev_client.get("/api/enterprise/v1/me")
    assert resp.status_code == 401
    assert "Development identity required" in resp.json()["detail"]


def test_16_development_authentication_rejects_non_loopback(dev_app):
    # Non-loopback client IP
    remote_client = TestClient(dev_app, client=("192.168.1.50", 50000))
    resp = remote_client.get(
        "/api/enterprise/v1/me",
        headers={
            "X-Dev-User": "external.intruder",
            "X-Dev-Roles": "investigator",
        },
    )
    assert resp.status_code == 403
    assert "Development access is local only" in resp.json()["detail"]


def test_17_development_authentication_forbidden_in_production():
    settings = EnterpriseSettings(
        environment="production",
        auth_mode="development",
    )
    with pytest.raises(RuntimeError, match="Development authentication is forbidden in production"):
        settings.validate()


def test_17b_production_requires_oidc():
    settings = EnterpriseSettings(
        environment="production",
        auth_mode="other",
    )
    with pytest.raises(RuntimeError, match="Production Enterprise API requires OIDC"):
        settings.validate()
