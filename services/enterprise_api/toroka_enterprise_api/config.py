"""Enterprise API configuration and validation."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

VALID_ROLES = {
    "investigator",
    "authoriser",
    "auditor",
    "data_steward",
    "system_administrator",
}


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

        return cls(
            environment=os.getenv("TOROKA_ENT_ENV", "development"),
            auth_mode=os.getenv("TOROKA_ENT_AUTH_MODE", "oidc"),
            oidc_issuer=os.getenv("TOROKA_ENT_OIDC_ISSUER", ""),
            oidc_audience=os.getenv("TOROKA_ENT_OIDC_AUDIENCE", ""),
            oidc_jwks_url=os.getenv("TOROKA_ENT_OIDC_JWKS_URL", ""),
            role_claim=os.getenv("TOROKA_ENT_ROLE_CLAIM", "groups"),
            algorithms=algorithms or ("RS256",),
            role_map=role_map,
            database_url=os.getenv("TOROKA_ENT_DATABASE_URL", "sqlite:///./enterprise_operational.db"),
            vault_database_url=os.getenv("TOROKA_ENT_VAULT_DATABASE_URL", "sqlite:///./enterprise_vault.db"),
            vault_key=os.getenv("TOROKA_ENT_VAULT_KEY", ""),
            vault_key_version=os.getenv("TOROKA_ENT_VAULT_KEY_VERSION", "v1"),
            installation_id=os.getenv("TOROKA_ENT_INSTALLATION_ID", "toroka-default-installation"),
        )

    def validate(self) -> None:
        if self.auth_mode == "development":
            if self.environment == "production":
                raise RuntimeError("Development authentication is forbidden in production")
            return
        if self.environment == "production":
            if self.auth_mode != "oidc":
                raise RuntimeError("Production Enterprise API requires OIDC")
            from sqlalchemy.engine import make_url
            op_url = make_url(self.database_url)
            if op_url.get_backend_name() != "postgresql":
                raise RuntimeError("Production Enterprise persistence requires PostgreSQL")
            vault_url = make_url(self.vault_database_url)
            if vault_url.get_backend_name() != "postgresql":
                raise RuntimeError("Production Enterprise vault requires PostgreSQL")
            if self.database_url == self.vault_database_url:
                raise RuntimeError("Operational database and identity vault must use separate database URLs")
            if not self.vault_key:
                raise RuntimeError("Production Enterprise API requires TOROKA_ENT_VAULT_KEY")
        if self.auth_mode not in {"oidc", "development"}:
            raise ValueError("Unsupported authentication mode")
        if not all((self.oidc_issuer, self.oidc_audience, self.oidc_jwks_url)):
            raise RuntimeError("OIDC issuer, audience and JWKS URL are required")
        if not self.algorithms or any(a not in {"RS256", "ES256"} for a in self.algorithms):
            raise ValueError("Unsupported JWT signing algorithm")
        if any(role not in VALID_ROLES for role in self.role_map.values()):
            raise ValueError("Role map contains an unknown Toroka role")
