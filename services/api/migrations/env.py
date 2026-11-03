import os
from alembic import context
from sqlalchemy import create_engine
from app.db import Base

url = os.environ.get("DATABASE_URL", "sqlite:///./ssi.db")


def run():
    if context.is_offline_mode():
        context.configure(url=url, target_metadata=Base.metadata, literal_binds=True)
        with context.begin_transaction():
            context.run_migrations()
        return
    engine = create_engine(url)
    with engine.connect() as conn:
        context.configure(connection=conn, target_metadata=Base.metadata, render_as_batch=url.startswith("sqlite"))
        with context.begin_transaction():
            context.run_migrations()


run()
