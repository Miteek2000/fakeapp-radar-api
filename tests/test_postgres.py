"""Pruebas contra un PostgreSQL real (migraciones incluidas).

Se saltan solas si no defines TEST_DATABASE_URL. Ejemplo (usa una base de PRUEBAS, porque
estas pruebas borran y vuelven a crear las tablas):
    $env:TEST_DATABASE_URL = "postgresql+psycopg://fakeapp:CLAVE@localhost:5434/fakeapp_test"
"""
import os
import uuid

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app import db, store
from app.config import settings
from app.schemas import AnalysisStatus

pytestmark = pytest.mark.skipif(not os.getenv("TEST_DATABASE_URL"), reason="Falta TEST_DATABASE_URL")

REPORTE = {"package_name": "com.banco.falso", "risk_score": 83, "risk_level": "alto", "permissions": ["READ_SMS"]}


@pytest.fixture
def pg(monkeypatch):
    url = os.environ["TEST_DATABASE_URL"]
    monkeypatch.setattr(settings, "database_url", url)
    cfg = Config("alembic.ini")
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")  # prueba también que la migración funciona
    engine = create_engine(url)
    monkeypatch.setattr(db, "_engine", engine)
    monkeypatch.setattr(db, "_session_factory", sessionmaker(engine, expire_on_commit=False))
    yield engine
    engine.dispose()
    command.downgrade(cfg, "base")


def test_ciclo_completo_en_postgres(pg):
    uid = uuid.uuid4()
    store.create(uid, "b" * 64, 4096)
    store.save(uid, AnalysisStatus.running)
    store.save(uid, AnalysisStatus.done, report=REPORTE)
    assert store.load(uid)["report"] == REPORTE

    with pg.connect() as c:
        row = c.execute(text("select report_enc, risk_score, risk_level, created_at, finished_at from analyses")).one()
    assert bytes(row.report_enc).find(b"com.banco.falso") == -1  # cifrado en la base
    assert (row.risk_score, row.risk_level) == (83, "alto")
    assert row.created_at is not None and row.finished_at is not None


def test_postgres_rechaza_datos_invalidos(pg):
    with pytest.raises(IntegrityError):
        with pg.begin() as c:
            c.execute(text("insert into analyses (id, status, sha256, size_bytes) values (gen_random_uuid(), 'x', :h, 1)"), {"h": "a" * 64})
    with pytest.raises(IntegrityError):
        with pg.begin() as c:
            c.execute(text("insert into analyses (id, status, sha256, size_bytes, risk_score) values (gen_random_uuid(), 'done', :h, 1, 150)"), {"h": "a" * 64})
