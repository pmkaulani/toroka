"""Alembic environment configuration for Toroka Enterprise persistence."""
import os
import sys
from pathlib import Path

_current_dir = Path(__file__).resolve().parent
_ent_api_dir = _current_dir.parent
if str(_ent_api_dir) not in sys.path:
    sys.path.insert(0, str(_ent_api_dir))
_root_dir = _ent_api_dir.parent.parent
if str(_root_dir) not in sys.path:
    sys.path.insert(0, str(_root_dir))

from alembic import context
from sqlalchemy import create_engine
from toroka_enterprise_api.persistence.models import Base

url = os.environ.get("TOROKA_ENT_DATABASE_URL", "sqlite:///./enterprise_operational.db")
if url.startswith("sqlite:///"):
    db_file = url[len("sqlite:///"):]
    if not db_file.startswith(":memory:") and db_file:
        db_dir = os.path.dirname(db_file)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)


def run():
    if context.is_offline_mode():
        context.configure(url=url, target_metadata=Base.metadata, literal_binds=True)
        with context.begin_transaction():
            context.run_migrations()
        return

    engine = create_engine(url)
    with engine.connect() as conn:
        context.configure(
            connection=conn,
            target_metadata=Base.metadata,
            render_as_batch=url.startswith("sqlite"),
        )
        with context.begin_transaction():
            context.run_migrations()


run()
