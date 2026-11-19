"""Configuration and validation for the isolated Identity Vault service."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from sqlalchemy.engine import make_url


def read_setting(name: str, default: str = "") -> str:
    file_path = os.getenv(f"{name}_FILE")
    if file_path:
        path = Path(file_path)
        if not path.is_file():
            raise RuntimeError(f"Required secret file for {name} is unavailable")
        value = path.read_text(encoding="utf-8").strip()
        if not value:
            raise RuntimeError(f"Required secret file for {name} is empty")
        return value
    return os.getenv(name, default)


@dataclass(frozen=True, slots=True)
class VaultSettings:
    environment: str = "development"
    database_url: str = "sqlite:///./enterprise_vault.db"
    service_token: str = ""
    encryption_mode: str = "envelope"
    kms_key_id: str = "alias/toroka-enterprise-identity-vault"
    vault_key: str = ""
    vault_key_version: str = "v1"
    master_kek: str = ""
    host: str = "0.0.0.0"
    port: int = 8200

    @classmethod
    def from_env(cls) -> "VaultSettings":
        return cls(
            environment=os.getenv("TOROKA_VAULT_ENV", "development"),
            database_url=read_setting("TOROKA_VAULT_DATABASE_URL", "sqlite:///./enterprise_vault.db"),
            service_token=read_setting("TOROKA_VAULT_SERVICE_TOKEN", "toroka-dev-internal-vault-token"),
            encryption_mode=os.getenv("TOROKA_VAULT_ENCRYPTION_MODE", "envelope"),
            kms_key_id=os.getenv("TOROKA_VAULT_KMS_KEY_ID", "alias/toroka-enterprise-identity-vault"),
            vault_key=read_setting("TOROKA_VAULT_KEY", ""),
            vault_key_version=os.getenv("TOROKA_VAULT_KEY_VERSION", "v1"),
            master_kek=read_setting("TOROKA_VAULT_MASTER_KEK", ""),
            host=os.getenv("TOROKA_VAULT_HOST", "0.0.0.0"),
            port=int(os.getenv("TOROKA_VAULT_PORT", "8200")),
        )

    def validate(self) -> None:
        if self.environment not in {"development", "test", "staging", "production"}:
            raise ValueError(f"Unsupported Vault environment: {self.environment}")

        if self.environment == "production":
            url = make_url(self.database_url)
            if url.get_backend_name() != "postgresql":
                raise RuntimeError("Production Identity Vault requires PostgreSQL")
            if not self.service_token or len(self.service_token) < 32:
                raise RuntimeError("Production Identity Vault requires a strong internal service token (at least 32 characters)")
            if self.vault_key:
                raise RuntimeError("Production Identity Vault must not use raw Fernet key")
            if not self.kms_key_id:
                raise RuntimeError("Production Identity Vault requires a configured KMS key ID")
            if not self.master_kek or len(self.master_kek.encode("utf-8")) < 32:
                raise RuntimeError("Production Identity Vault requires durable KMS master key material (at least 32 bytes). Ephemeral LocalKMS keys are refused in production.")
