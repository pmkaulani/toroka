"""Tests for Enterprise settings parsing and validation."""
from __future__ import annotations

import pytest

from toroka_enterprise_api.config import EnterpriseSettings


def test_config_from_env_defaults(monkeypatch):
    monkeypatch.delenv("TOROKA_ENT_ENV", raising=False)
    monkeypatch.delenv("TOROKA_ENT_AUTH_MODE", raising=False)
    monkeypatch.delenv("TOROKA_ENT_OIDC_ISSUER", raising=False)
    monkeypatch.delenv("TOROKA_ENT_ROLE_MAP_JSON", raising=False)

    cfg = EnterpriseSettings.from_env()
    assert cfg.environment == "development"
    assert cfg.auth_mode == "oidc"
    assert cfg.role_map == {}


def test_config_from_env_custom(monkeypatch):
    monkeypatch.setenv("TOROKA_ENT_ENV", "production")
    monkeypatch.setenv("TOROKA_ENT_AUTH_MODE", "oidc")
    monkeypatch.setenv("TOROKA_ENT_OIDC_ISSUER", "https://idp.bank.local")
    monkeypatch.setenv("TOROKA_ENT_OIDC_AUDIENCE", "toroka-ent")
    monkeypatch.setenv("TOROKA_ENT_OIDC_JWKS_URL", "https://idp.bank.local/jwks")
    monkeypatch.setenv("TOROKA_ENT_ROLE_MAP_JSON", '{"GRP_INV": "investigator"}')
    monkeypatch.setenv("TOROKA_ENT_DATABASE_URL", "postgresql+psycopg://db.bank.local/toroka")
    monkeypatch.setenv("TOROKA_ENT_VAULT_DATABASE_URL", "postgresql+psycopg://vault.bank.local/toroka_vault")
    monkeypatch.setenv("TOROKA_ENT_VAULT_KEY", "test-vault-secret-key")

    cfg = EnterpriseSettings.from_env()
    assert cfg.environment == "production"
    assert cfg.role_map == {"GRP_INV": "investigator"}
    cfg.validate()


def test_config_invalid_json_role_map(monkeypatch):
    monkeypatch.setenv("TOROKA_ENT_ROLE_MAP_JSON", "not-a-json")
    with pytest.raises(ValueError, match="Role map must be valid JSON"):
        EnterpriseSettings.from_env()


def test_config_non_dict_role_map(monkeypatch):
    monkeypatch.setenv("TOROKA_ENT_ROLE_MAP_JSON", '["not", "a", "dict"]')
    with pytest.raises(ValueError, match="Role map must be a JSON object"):
        EnterpriseSettings.from_env()


def test_config_unknown_role_in_role_map():
    cfg = EnterpriseSettings(
        environment="test",
        auth_mode="oidc",
        oidc_issuer="https://idp.bank.local",
        oidc_audience="aud",
        oidc_jwks_url="https://idp.bank.local/jwks",
        role_map={"EXT_ROLE": "super_mega_admin"},
    )
    with pytest.raises(ValueError, match="Role map contains an unknown Toroka role"):
        cfg.validate()


def test_config_unsupported_signing_algorithm():
    cfg = EnterpriseSettings(
        environment="test",
        auth_mode="oidc",
        oidc_issuer="https://idp.bank.local",
        oidc_audience="aud",
        oidc_jwks_url="https://idp.bank.local/jwks",
        algorithms=("HS256",),
    )
    with pytest.raises(ValueError, match="Unsupported JWT signing algorithm"):
        cfg.validate()
