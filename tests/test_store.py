import uuid

import pytest
from cryptography.exceptions import InvalidTag

from app import store
from app.db import session_scope
from app.models import Analysis
from app.schemas import AnalysisStatus

SHA = "a" * 64
REPORTE = {"package_name": "com.x", "risk_score": 40, "risk_level": "medio", "permissions": []}


def test_load_de_un_id_que_no_existe():
    assert store.load(uuid.uuid4()) is None


def test_ciclo_de_vida_pending_running_done():
    uid = uuid.uuid4()
    store.create(uid, SHA, 123)
    assert store.load(uid) == {"id": str(uid), "status": "pending", "report": None, "error": None, "virustotal": None}

    store.save(uid, AnalysisStatus.running)
    assert store.load(uid)["status"] == "running"

    store.save(uid, AnalysisStatus.done, report=REPORTE)
    data = store.load(uid)
    assert data["status"] == "done"
    assert data["report"] == REPORTE
    with session_scope() as s:
        assert s.get(Analysis, uid).finished_at is not None


def test_failed_guarda_el_error():
    uid = uuid.uuid4()
    store.create(uid, SHA, 1)
    store.save(uid, AnalysisStatus.failed, error="El APK no tiene AndroidManifest.xml")
    data = store.load(uid)
    assert data["status"] == "failed"
    assert data["error"] == "El APK no tiene AndroidManifest.xml"
    assert data["report"] is None


def test_guardar_sobre_un_id_inexistente_no_revienta():
    store.save(uuid.uuid4(), AnalysisStatus.running)  # solo se avisa en el log


def test_discard_borra_el_registro():
    uid = uuid.uuid4()
    store.create(uid, SHA, 1)
    store.discard(uid)
    assert store.load(uid) is None


def test_un_reporte_movido_a_otra_fila_no_se_lee():
    a, b = uuid.uuid4(), uuid.uuid4()
    store.create(a, SHA, 1)
    store.create(b, SHA, 1)
    store.save(a, AnalysisStatus.done, report=REPORTE)
    with session_scope() as s:
        s.get(Analysis, b).report_enc = s.get(Analysis, a).report_enc  # simula manipular la base
        s.get(Analysis, b).status = "done"
    with pytest.raises(InvalidTag):
        store.load(b)


def test_la_base_rechaza_un_estado_invalido():
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError):
        with session_scope() as s:
            s.add(Analysis(id=uuid.uuid4(), status="inventado", sha256=SHA, size_bytes=1))
