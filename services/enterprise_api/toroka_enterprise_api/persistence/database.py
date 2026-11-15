"""Database engine and session management for Enterprise persistence."""
from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session, sessionmaker


def build_engine(
    database_url: str,
    *,
    production: bool,
) -> Engine:
    parsed = make_url(database_url)
    if production and parsed.get_backend_name() != "postgresql":
        raise RuntimeError(
            "Production Enterprise persistence requires PostgreSQL"
        )
    if parsed.get_backend_name() == "sqlite":
        return create_engine(
            database_url,
            connect_args={"check_same_thread": False},
        )
    return create_engine(
        database_url,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
        pool_recycle=1800,
    )


def build_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(
        bind=engine,
        class_=Session,
        autoflush=False,
        expire_on_commit=False,
    )


def session_dependency(
    factory: sessionmaker[Session],
) -> Generator[Session, None, None]:
    db = factory()
    try:
        yield db
    finally:
        db.close()
