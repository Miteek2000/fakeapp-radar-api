import os
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app import store
from app.config import settings
from app.db import session_scope
from app.models import Analysis
from app.worker import maintenance
from app.worker.celery_app import celery_app


def crear(dias_atras: float, estado: str = "done") -> uuid.UUID:
    uid = uuid.uuid4()
    with session_scope() as s:
        s.add(Analysis(id=uid, status=estado, sha256="a" * 64, size_bytes=1,
                       created_at=datetime.now(timezone.utc) - timedelta(days=dias_atras)))
    return uid


def ids() -> set[uuid.UUID]:
    with session_scope() as s:
        return set(s.scalars(select(Analysis.id)))


def test_borra_solo_los_analisis_mas_viejos_que_el_limite():
    viejo, limite_justo_antes, reciente = crear(45), crear(31), crear(29)
    borrados = store.purge_older_than(30)
    assert borrados == 2
    assert ids() == {reciente}


def test_borra_tambien_los_que_quedaron_atorados():
    atorado = crear(40, estado="running")
    assert store.purge_older_than(30) == 1 and atorado not in ids()


def test_sin_nada_que_borrar_devuelve_cero():
    crear(1)
    assert store.purge_older_than(30) == 0 and len(ids()) == 1


def archivo(carpeta, nombre: str, horas_atras: float):
    f = carpeta / nombre
    f.write_bytes(b"x")
    t = time.time() - horas_atras * 3600
    os.utime(f, (t, t))
    return f


def test_borra_apk_sueltos_viejos_y_deja_lo_demas(tmp_path):
    viejo = archivo(tmp_path, "viejo.apk", 30)
    reciente = archivo(tmp_path, "reciente.apk", 2)
    otro = archivo(tmp_path, "notas.txt", 100)
    (tmp_path / "carpeta.apk").mkdir()
    assert maintenance.purge_orphan_uploads(tmp_path, 24) == 1
    assert not viejo.exists() and reciente.exists() and otro.exists() and (tmp_path / "carpeta.apk").exists()


def test_no_sigue_enlaces_simbolicos(tmp_path):
    fuera = archivo(tmp_path, "secreto.txt", 100)
    carpeta = tmp_path / "up"; carpeta.mkdir()
    try:
        (carpeta / "enlace.apk").symlink_to(fuera)
    except (OSError, NotImplementedError):
        pytest.skip("Este sistema no permite crear enlaces simbólicos (en Windows requiere privilegios)")
    assert maintenance.purge_orphan_uploads(carpeta, 0) == 0 and fuera.exists()


def test_carpeta_inexistente_no_falla(tmp_path):
    assert maintenance.purge_orphan_uploads(tmp_path / "no-existe", 24) == 0


def test_la_tarea_programada_usa_la_configuracion(monkeypatch):
    monkeypatch.setattr(settings, "retention_days", 10)
    monkeypatch.setattr(settings, "orphan_upload_hours", 1)
    crear(15); crear(5)
    resultado = maintenance.purge_expired_task.apply().get()
    assert resultado["analyses_deleted"] == 1 and len(ids()) == 1


def test_la_limpieza_esta_programada_cada_dia():
    entrada = celery_app.conf.beat_schedule["purge-expired"]
    assert entrada["task"] == "purge_expired"
    assert "purge_expired" in celery_app.tasks
