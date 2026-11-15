"""Shared fixtures and test helpers for Toroka Enterprise API."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

import jwt
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt import PyJWK
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from toroka_enterprise_api.config import EnterpriseSettings
from toroka_enterprise_api.main import create_app
from toroka_enterprise_api.persistence.audit import GENESIS_HASH
from toroka_enterprise_api.persistence.models import AuditHead, Base
from toroka_enterprise_api.persistence.vault import (
    FernetVaultCipher,
    IdentityVaultRepository,
    VaultBase,
)
from toroka_enterprise.integrations.models import IntegrationBase
from toroka_enterprise_api.services.cases import CaseService
from toroka_enterprise_api.services.reveals import RevealService
from toroka_enterprise_api.services.runs import RunService


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
def test_vault_key():
    return Fernet.generate_key().decode("utf-8")


@pytest.fixture
def test_vault_key_v2():
    return Fernet.generate_key().decode("utf-8")


@pytest.fixture
def test_vault_cipher(test_vault_key, test_vault_key_v2):
    return FernetVaultCipher(
        {"v1": test_vault_key, "v2": test_vault_key_v2},
        current_version="v1",
    )


@pytest.fixture
def db_engine():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    IntegrationBase.metadata.create_all(engine)
    with Session(engine) as session:
        head = AuditHead(
            installation_id="toroka-default-installation",
            last_sequence=0,
            last_hash=GENESIS_HASH,
        )
        session.add(head)
        session.commit()
    yield engine
    IntegrationBase.metadata.drop_all(engine)
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def db_session(db_engine):
    with Session(db_engine, autoflush=False, expire_on_commit=False) as session:
        yield session


@pytest.fixture
def vault_engine():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    VaultBase.metadata.create_all(engine)
    yield engine
    VaultBase.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def vault_db_session(vault_engine):
    with Session(vault_engine, autoflush=False, expire_on_commit=False) as session:
        yield session


@pytest.fixture
def test_vault_repo(vault_db_session, test_vault_cipher):
    return IdentityVaultRepository(vault_db_session, test_vault_cipher)


@pytest.fixture
def test_case_service(db_session):
    return CaseService(db_session)


@pytest.fixture
def test_reveal_service(db_session, test_vault_repo):
    return RevealService(db_session, test_vault_repo)


@pytest.fixture
def test_run_service(db_session):
    return RunService(db_session)


@pytest.fixture
def oidc_settings(test_vault_key):
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
        database_url="sqlite:///:memory:",
        vault_database_url="sqlite:///:memory:",
        vault_key=test_vault_key,
        vault_key_version="v1",
        installation_id="toroka-default-installation",
    )


@pytest.fixture
def oidc_app(oidc_settings, mock_jwks, db_engine, vault_engine, test_vault_cipher):
    app = create_app(oidc_settings)
    app.state.jwks_client = mock_jwks
    app.state.engine = db_engine
    app.state.session_factory = sessionmaker(
        bind=db_engine, class_=Session, autoflush=False, expire_on_commit=False
    )
    app.state.vault_engine = vault_engine
    app.state.vault_session_factory = sessionmaker(
        bind=vault_engine, class_=Session, autoflush=False, expire_on_commit=False
    )
    app.state.vault_cipher = test_vault_cipher
    return app


@pytest.fixture
def oidc_client(oidc_app):
    return TestClient(oidc_app, client=("127.0.0.1", 50000))


@pytest.fixture
def dev_settings(test_vault_key):
    return EnterpriseSettings(
        environment="development",
        auth_mode="development",
        database_url="sqlite:///:memory:",
        vault_database_url="sqlite:///:memory:",
        vault_key=test_vault_key,
        vault_key_version="v1",
        installation_id="toroka-default-installation",
    )


@pytest.fixture
def dev_app(dev_settings, db_engine, vault_engine, test_vault_cipher):
    app = create_app(dev_settings)
    app.state.engine = db_engine
    app.state.session_factory = sessionmaker(
        bind=db_engine, class_=Session, autoflush=False, expire_on_commit=False
    )
    app.state.vault_engine = vault_engine
    app.state.vault_session_factory = sessionmaker(
        bind=vault_engine, class_=Session, autoflush=False, expire_on_commit=False
    )
    app.state.vault_cipher = test_vault_cipher
    return app


@pytest.fixture
def dev_client(dev_app):
    return TestClient(dev_app, client=("127.0.0.1", 50000))


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
