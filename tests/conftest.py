import base64

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import db
from app.config import settings
from app.models import PermissionCatalog
from app.worker.celery_app import celery_app
from tests.catalogo_prueba import FILAS

# Clave de prueba (32 bytes en base64). La real vive solo en el .env de cada ambiente.
TEST_KEY = base64.b64encode(b"k" * 32).decode()


@pytest.fixture(autouse=True)
def entorno_de_pruebas(tmp_path, monkeypatch):
    """Cada prueba usa una base SQLite en memoria, una carpeta de subidas propia, una
    clave de cifrado de prueba y Celery en modo 'eager' (la tarea corre al instante,
    sin worker ni broker)."""
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,  # una sola conexión compartida entre los hilos de la prueba
    )
    db.Base.metadata.create_all(engine)
    with sessionmaker(engine)() as s:  # la tabla del catálogo se llena como lo haría el repo -db
        s.add_all(PermissionCatalog(android_name=f[0], friendly_title=f[1], explanation=f[2], severity=f[3], weight=f[4], icon=f[5]) for f in FILAS)
        s.commit()
    monkeypatch.setattr(db, "_engine", engine)
    monkeypatch.setattr(db, "_session_factory", sessionmaker(engine, expire_on_commit=False))
    monkeypatch.setattr(settings, "upload_dir", str(tmp_path / "uploads"))
    monkeypatch.setattr(settings, "encryption_key", TEST_KEY)

    # Se asigna y se restaura a mano: monkeypatch intenta borrar el atributo al
    # terminar y el objeto de configuracion de Celery no lo permite.
    anterior = celery_app.conf.task_always_eager
    celery_app.conf.task_always_eager = True
    try:
        yield
    finally:
        celery_app.conf.task_always_eager = anterior
        engine.dispose()
