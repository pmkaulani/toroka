"""Alembic environment configuration for Toroka Enterprise Identity Vault."""
import os
from alembic import context
from sqlalchemy import create_engine
from toroka_enterprise_api.persistence.vault import VaultBase

url = os.environ.get("TOROKA_ENT_VAULT_DATABASE_URL", "sqlite:///./enterprise_vault.db")
if url.startswith("sqlite:///"):
    db_file = url[len("sqlite:///"):]
    if not db_file.startswith(":memory:") and db_file:
        db_dir = os.path.dirname(db_file)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)


def run():
    if context.is_offline_mode():
        context.configure(url=url, target_metadata=VaultBase.metadata, literal_binds=True)
        with context.begin_transaction():
            context.run_migrations()
        return

    engine = create_engine(url)
    with engine.connect() as conn:
        context.configure(
            connection=conn,
            target_metadata=VaultBase.metadata,
            render_as_batch=url.startswith("sqlite"),
        )
        with context.begin_transaction():
            context.run_migrations()


run()
