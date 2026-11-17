import hashlib
import io
import uuid
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

from app import store
from app.db import session_scope
from app.models import Analysis
from app.worker.tasks import analyze_apk_task
from app.config import settings
from app.main import app
from tests.apk_factory import make_apk

client = TestClient(app)


def zip_con_texto() -> bytes:
    """Un ZIP que pasa la validación de la subida pero NO es un APK real."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", "contenido de prueba")
    return buf.getvalue()


def upload(name: str, data: bytes):
    return client.post("/analyses", files={"file": (name, data, "application/octet-stream")})


def upload_dir_vacia() -> bool:
    return list(Path(settings.upload_dir).iterdir()) == []


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_subida_y_consulta_del_resultado(tmp_path):
    apk = make_apk(tmp_path / "banco.apk", permissions=["READ_SMS", "BIND_ACCESSIBILITY_SERVICE", "CAMERA"])
    data = apk.read_bytes()

    r = upload("banco.apk", data)
    assert r.status_code == 202
    body = r.json()
    assert body["sha256"] == hashlib.sha256(data).hexdigest()
    assert body["size_bytes"] == len(data)
    assert body["status"] == "pending"

    r = client.get(f"/analyses/{body['id']}")
    assert r.status_code == 200
    result = r.json()
    assert result["status"] == "done"
    assert result["error"] is None
    assert result["report"]["risk_score"] == 47  # 20 + 25 + 2
    assert result["report"]["risk_level"] == "medio"
    assert result["report"]["hashes"]["sha256"] == hashlib.sha256(data).hexdigest()
    # el APK se borra del disco al terminar
    assert upload_dir_vacia()


def test_apk_ilegible_queda_como_failed():
    r = upload("falso.apk", zip_con_texto())
    assert r.status_code == 202
    result = client.get(f"/analyses/{r.json()['id']}").json()
    assert result["status"] == "failed"
    assert result["report"] is None
    assert "APK" in result["error"]
    assert upload_dir_vacia()


def test_consulta_de_un_id_que_no_existe():
    assert client.get(f"/analyses/{uuid.uuid4()}").status_code == 404


def test_consulta_con_id_invalido():
    assert client.get("/analyses/no-es-un-uuid").status_code == 422


def test_rechaza_extension_incorrecta():
    assert upload("foto.png", zip_con_texto()).status_code == 400


def test_rechaza_contenido_que_no_es_apk():
    r = upload("falso.apk", b"esto es solo texto")
    assert r.status_code == 400
    assert upload_dir_vacia()


def test_rechaza_archivo_vacio():
    assert upload("vacio.apk", b"").status_code == 400


def test_rechaza_archivo_muy_grande(monkeypatch):
    monkeypatch.setattr(settings, "max_upload_mb", 0)
    r = upload("grande.apk", zip_con_texto())
    assert r.status_code == 413
    assert upload_dir_vacia()


def test_si_la_base_de_datos_falla_responde_503_y_no_deja_archivos(monkeypatch):
    def base_caida(*args, **kwargs):
        raise ConnectionError("La base de datos no responde")

    monkeypatch.setattr(store, "create", base_caida)
    r = upload("app.apk", zip_con_texto())
    assert r.status_code == 503
    assert upload_dir_vacia()


def test_si_la_cola_falla_responde_503_y_no_deja_registros_ni_archivos(monkeypatch):
    def cola_caida(*args, **kwargs):
        raise ConnectionError("Redis no responde")

    monkeypatch.setattr(analyze_apk_task, "delay", cola_caida)
    r = upload("app.apk", zip_con_texto())
    assert r.status_code == 503
    assert upload_dir_vacia()
    with session_scope() as s:
        assert s.query(Analysis).count() == 0  # no queda un análisis "pending" huérfano


def test_el_resultado_persiste_y_se_puede_consultar_varias_veces(tmp_path):
    apk = make_apk(tmp_path / "a.apk", permissions=["CAMERA"])
    analysis_id = upload("a.apk", apk.read_bytes()).json()["id"]
    primero = client.get(f"/analyses/{analysis_id}").json()
    segundo = client.get(f"/analyses/{analysis_id}").json()
    assert primero == segundo
    assert primero["status"] == "done"
