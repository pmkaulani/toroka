"""Shared fixtures and test helpers for Toroka Enterprise API."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt import PyJWK
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError

from toroka_enterprise_api.config import EnterpriseSettings
from toroka_enterprise_api.main import create_app


@pytest.fixture(scope="session")
def primary_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def secondary_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def primary_jwk_dict(primary_key):
    pub_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(primary_key.public_key())
    d = json.loads(pub_jwk)
    d["kid"] = "key-primary"
    return d


@pytest.fixture(scope="session")
def secondary_jwk_dict(secondary_key):
    pub_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(secondary_key.public_key())
    d = json.loads(pub_jwk)
    d["kid"] = "key-secondary"
    return d


class MockJWKClient:
    """Mock JWKS client simulating key retrieval, rotation, and connection errors."""

    def __init__(self, initial_keys: list[dict[str, Any]] | None = None):
        self.keys: dict[str, PyJWK] = {
            k["kid"]: PyJWK.from_dict(k) for k in (initial_keys or [])
        }
        self.fetch_count = 0
        self.simulate_connection_failure = False

    def add_key(self, key_dict: dict[str, Any]) -> None:
        self.keys[key_dict["kid"]] = PyJWK.from_dict(key_dict)

    def get_signing_key_from_jwt(self, token: str) -> PyJWK:
        self.fetch_count += 1
        if self.simulate_connection_failure:
            raise PyJWKClientConnectionError("Mock IDP network timeout")

        try:
            headers = jwt.get_unverified_header(token)
        except Exception as e:
            raise PyJWKClientError(f"Invalid token header: {e}")

        kid = headers.get("kid")
        if not kid or kid not in self.keys:
            raise PyJWKClientError(f"Signing key '{kid}' not found in JWKS")

        return self.keys[kid]


@pytest.fixture
def mock_jwks(primary_jwk_dict):
    return MockJWKClient([primary_jwk_dict])


@pytest.fixture
def oidc_settings():
    return EnterpriseSettings(
        environment="test",
        auth_mode="oidc",
        oidc_issuer="https://idp.bank.local",
        oidc_audience="toroka-enterprise",
        oidc_jwks_url="https://idp.bank.local/.well-known/jwks.json",
        role_claim="groups",
        algorithms=("RS256",),
        role_map={
            "BANK_INVESTIGATOR": "investigator",
            "BANK_AUTHORISER": "authoriser",
            "BANK_AUDITOR": "auditor",
            "BANK_DATA_STEWARD": "data_steward",
            "BANK_SYSADMIN": "system_administrator",
        },
    )


@pytest.fixture
def oidc_app(oidc_settings, mock_jwks):
    app = create_app(oidc_settings)
    app.state.jwks_client = mock_jwks
    return app


@pytest.fixture
def oidc_client(oidc_app):
    return TestClient(oidc_app, client=("127.0.0.1", 50000))


@pytest.fixture
def token_factory(primary_key):
    def _create_token(
        *,
        sub: str = "investigator.alice",
        roles: list[str] | None = None,
        iss: str = "https://idp.bank.local",
        aud: str = "toroka-enterprise",
        kid: str = "key-primary",
        key: Any = None,
        algorithm: str = "RS256",
        exp_offset: int = 300,
        iat_offset: int = 0,
        role_claim: str = "groups",
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        signing_key = key or primary_key
        now = int(time.time())
        claims = {
            "sub": sub,
            "iss": iss,
            "aud": aud,
            "iat": now + iat_offset,
            "exp": now + exp_offset,
        }
        if roles is not None:
            claims[role_claim] = roles
        if extra_claims:
            claims.update(extra_claims)

        headers = {"kid": kid} if kid else None
        return jwt.encode(claims, signing_key, algorithm=algorithm, headers=headers)

    return _create_token


@pytest.fixture
def dev_settings():
    return EnterpriseSettings(
        environment="development",
        auth_mode="development",
    )


@pytest.fixture
def dev_app(dev_settings):
    return create_app(dev_settings)


@pytest.fixture
def dev_client(dev_app):
    return TestClient(dev_app, client=("127.0.0.1", 50000))
