import fakeredis
import pytest

from app import store
from app.config import settings
from app.worker.celery_app import celery_app


@pytest.fixture(autouse=True)
def entorno_de_pruebas(tmp_path, monkeypatch):
    """Cada prueba usa un Redis simulado, una carpeta de subidas propia y
    Celery en modo 'eager' (la tarea corre al instante, sin worker ni broker)."""
    monkeypatch.setattr(store, "_client", fakeredis.FakeRedis(decode_responses=True))
    monkeypatch.setattr(settings, "upload_dir", str(tmp_path / "uploads"))
    
    anterior = celery_app.conf.task_always_eager
    celery_app.conf.task_always_eager = True
    try:
        yield
    finally:
        celery_app.conf.task_always_eager = anterior