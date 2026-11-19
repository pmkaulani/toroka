"""Enterprise API configuration and validation."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from sqlalchemy.engine import make_url

VALID_ROLES = {
    "investigator",
    "authoriser",
    "auditor",
    "data_steward",
    "system_administrator",
}


def read_setting(name: str, default: str = "") -> str:
    """Read a setting from an environment variable or a mounted secret file.
    
    If <name>_FILE is specified, the content of that file is read and stripped.
    This pattern supports Docker secrets and Kubernetes Secret volume mounts.
    """
    file_path = os.getenv(f"{name}_FILE")
    if file_path:
        path = Path(file_path)
        if not path.is_file():
            raise RuntimeError(
                f"Required secret file for {name} is unavailable"
            )
        value = path.read_text(encoding="utf-8").strip()
        if not value:
            raise RuntimeError(
                f"Required secret file for {name} is empty"
            )
        return value
    return os.getenv(name, default)


@dataclass(frozen=True, slots=True)
class EnterpriseSettings:
    environment: str = "development"
    auth_mode: str = "oidc"
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_jwks_url: str = ""
    role_claim: str = "groups"
    algorithms: tuple[str, ...] = ("RS256",)
    role_map: dict[str, str] = field(default_factory=dict)
    database_url: str = "sqlite:///./enterprise_operational.db"
    vault_database_url: str = "sqlite:///./enterprise_vault.db"
    vault_key: str = ""
    vault_key_version: str = "v1"
    installation_id: str = "toroka-default-installation"
    cors_allowed_origins: tuple[str, ...] = ()
    vault_service_url: str = ""
    vault_service_token: str = ""
    expected_schema_revision: str = ""

    @classmethod
    def from_env(cls) -> "EnterpriseSettings":
        raw_role_map = os.getenv("TOROKA_ENT_ROLE_MAP_JSON", "{}")
        try:
            role_map = json.loads(raw_role_map)
        except Exception as e:
            raise ValueError(f"Role map must be valid JSON: {e}")
        if not isinstance(role_map, dict):
            raise ValueError("Role map must be a JSON object")

        raw_algos = os.getenv("TOROKA_ENT_OIDC_ALGORITHMS", "RS256")
        algorithms = tuple(a.strip() for a in raw_algos.split(",") if a.strip())

        raw_origins = os.getenv("TOROKA_ENT_CORS_ORIGINS", "")
        cors_origins = tuple(
            origin.strip().rstrip("/")
            for origin in raw_origins.split(",")
            if origin.strip()
        )

        return cls(
            environment=os.getenv("TOROKA_ENT_ENV", "development"),
            auth_mode=os.getenv("TOROKA_ENT_AUTH_MODE", "oidc"),
            oidc_issuer=os.getenv("TOROKA_ENT_OIDC_ISSUER", ""),
            oidc_audience=os.getenv("TOROKA_ENT_OIDC_AUDIENCE", ""),
            oidc_jwks_url=os.getenv("TOROKA_ENT_OIDC_JWKS_URL", ""),
            role_claim=os.getenv("TOROKA_ENT_ROLE_CLAIM", "groups"),
            algorithms=algorithms or ("RS256",),
            role_map=role_map,
            database_url=read_setting("TOROKA_ENT_DATABASE_URL", "sqlite:///./enterprise_operational.db"),
            vault_database_url=read_setting("TOROKA_ENT_VAULT_DATABASE_URL", "sqlite:///./enterprise_vault.db"),
            vault_key=read_setting("TOROKA_ENT_VAULT_KEY", ""),
            vault_key_version=os.getenv("TOROKA_ENT_VAULT_KEY_VERSION", "v1"),
            installation_id=read_setting("TOROKA_ENT_INSTALLATION_ID", "toroka-default-installation"),
            cors_allowed_origins=cors_origins,
            vault_service_url=read_setting("TOROKA_ENT_VAULT_SERVICE_URL", ""),
            vault_service_token=read_setting("TOROKA_ENT_VAULT_SERVICE_TOKEN", ""),
            expected_schema_revision=read_setting("TOROKA_ENT_EXPECTED_SCHEMA_REVISION", ""),
        )

    def validate(self) -> None:
        if self.environment not in {
            "development",
            "test",
            "staging",
            "production",
        }:
            raise ValueError("Unsupported Enterprise environment")
        if self.environment == "production":
            if self.auth_mode == "development":
                raise RuntimeError(
                    "Development authentication is forbidden in production. Production requires bank-controlled OIDC"
                )
            if self.auth_mode != "oidc":
                raise RuntimeError(
                    "Production Enterprise API requires OIDC"
                )
            if self.vault_key:
                raise RuntimeError(
                    "Production must not use a raw Fernet key "
                    "inside the Enterprise API"
                )
            if not self.vault_service_url:
                raise RuntimeError(
                    "Production requires the internal Identity Vault service"
                )
            if not self.expected_schema_revision:
                raise RuntimeError(
                    "Expected production schema revision is required"
                )
            op_url = make_url(self.database_url)
            if op_url.get_backend_name() != "postgresql":
                raise RuntimeError("Production Enterprise persistence requires PostgreSQL")
            for origin in self.cors_allowed_origins:
                parsed = urlparse(origin)
                if parsed.scheme != "https" or not parsed.netloc or origin == "*":
                    raise RuntimeError("Production CORS origins must use HTTPS and specify a valid host")
            if len(self.vault_service_token) < 32:
                raise RuntimeError("Production Identity Vault service token must be at least 32 characters")
            if not self.oidc_issuer.startswith("https://") or not self.oidc_jwks_url.startswith("https://"):
                raise RuntimeError("Production OIDC issuer and JWKS URL must use HTTPS")
            fed_salt = os.environ.get("TOROKA_FEDERATED_MULE_SALT", "")
            if fed_salt == "TOROKA_CONSORTIUM_MULE_SALT_KENYA_CBK_2026_V1":
                raise RuntimeError("Production cannot use the default sample federation salt")
        if self.auth_mode not in {"oidc", "development"}:
            raise ValueError("Unsupported authentication mode")
        if self.auth_mode == "oidc":
            if not all((self.oidc_issuer, self.oidc_audience, self.oidc_jwks_url)):
                raise RuntimeError("OIDC issuer, audience and JWKS URL are required")
            if not self.algorithms or any(a not in {"RS256", "ES256"} for a in self.algorithms):
                raise ValueError("Unsupported JWT signing algorithm")
        if any(role not in VALID_ROLES for role in self.role_map.values()):
            raise ValueError("Role map contains an unknown Toroka role")
