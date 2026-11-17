"""Conexión a PostgreSQL con SQLAlchemy (síncrona: la usan la API en hilos y el worker)."""
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings


class Base(DeclarativeBase):
    pass


_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    """Crea el motor la primera vez que se necesita (así cada proceso del worker tiene el suyo)."""
    global _engine, _session_factory
    if _engine is None:
        if not settings.database_url:
            raise RuntimeError("Falta DATABASE_URL en la configuración (.env)")
        # pool_pre_ping revisa que la conexión siga viva antes de usarla.
        _engine = create_engine(settings.database_url, pool_pre_ping=True)
        _session_factory = sessionmaker(_engine, expire_on_commit=False)
    return _engine


@contextmanager
def session_scope() -> Iterator[Session]:
    """Una transacción: se confirma si todo sale bien y se revierte si hay un error."""
    get_engine()
    assert _session_factory is not None
    session = _session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
