"""Pruebas contra el PostgreSQL REAL del repo fakeapp-radar-db (ya migrado).

Se saltan solas si no defines TEST_DATABASE_URL. Levanta antes la base:
    cd ..\\..\\DB\\fakeapp-radar-db ; docker compose up -d --build
y usa una base de PRUEBAS (estas pruebas insertan y borran filas de `analyses`):
    $env:TEST_DATABASE_URL = "postgresql+psycopg://fakeapp:CLAVE@localhost:5433/fakeapp_test"
(la base de pruebas se migra con el migrador de ese repo; ver su README)
"""
import os
import uuid

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app import db, store
from app.analysis.catalog import load_catalog
from app.models import Analysis, PermissionCatalog
from app.schemas import AnalysisStatus

pytestmark = pytest.mark.skipif(not os.getenv("TEST_DATABASE_URL"), reason="Falta TEST_DATABASE_URL")

REPORTE = {"package_name": "com.banco.falso", "risk_score": 83, "risk_level": "alto", "permissions": ["READ_SMS"]}


@pytest.fixture
def pg(monkeypatch):
    engine = create_engine(os.environ["TEST_DATABASE_URL"])
    monkeypatch.setattr(db, "_engine", engine)
    monkeypatch.setattr(db, "_session_factory", sessionmaker(engine, expire_on_commit=False))
    with engine.begin() as c:
        c.execute(text("delete from analyses"))
    yield engine
    with engine.begin() as c:
        c.execute(text("delete from analyses"))
    engine.dispose()


def test_el_mapeo_de_la_api_coincide_con_la_tabla_real(pg):
    """Si alguien cambia la tabla en el repo -db (o el modelo aquí) y no el otro, esto avisa."""
    real = {c["name"]: c for c in inspect(pg).get_columns("analyses")}
    modelo = {c.name: c for c in Analysis.__table__.columns}
    assert set(real) == set(modelo)
    for nombre, col in modelo.items():
        assert real[nombre]["nullable"] == col.nullable, f"nullable distinto en {nombre}"


def test_el_mapeo_del_catalogo_coincide_con_la_tabla_real(pg):
    real = {c["name"]: c for c in inspect(pg).get_columns("permission_catalog")}
    modelo = {c.name: c for c in PermissionCatalog.__table__.columns}
    assert set(real) == set(modelo)
    for nombre, col in modelo.items():
        assert real[nombre]["nullable"] == col.nullable, f"nullable distinto en {nombre}"


def test_lee_el_catalogo_real_cargado_por_el_repo_db(pg):
    """Necesita que la base de pruebas tenga corrido el migrador (tablas + seeds)."""
    with db.session_scope() as s:
        cat = load_catalog(s)
    assert len(cat) >= 1000  # capa automática de AOSP + capa curada
    assert cat["android.permission.BIND_ACCESSIBILITY_SERVICE"].severity == "peligroso"


def test_todo_el_catalogo_tiene_fuente_y_nivel_de_proteccion(pg):
    with pg.connect() as c:
        mal = c.execute(text("select android_name from permission_catalog where source is null or source = '' or protection_level is null")).all()
        sin_aosp = c.execute(text("select android_name from permission_catalog where source not like '%AOSP%'")).all()
    assert mal == [] and sin_aosp == []


def test_la_capa_curada_manda_sobre_la_automatica(pg):
    with db.session_scope() as s:
        cat = load_catalog(s)
    sms = cat["android.permission.READ_SMS"]
    assert sms.severity == "peligroso" and sms.weight == 20 and sms.friendly_title == "Leer tus mensajes SMS"
    generico = cat["android.permission.ACCEPT_HANDOVER"]
    assert generico.severity == "atencion" and generico.weight == 4
    with pg.connect() as c:
        assert c.execute(text("select count(*) from permission_catalog where curated")).scalar() >= 52


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
