import hashlib
import io
import zipfile

from fastapi.testclient import TestClient

from app.config import settings
from app.main import app

client = TestClient(app)


def fake_apk() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", "contenido de prueba")
    return buf.getvalue()


def upload(name: str, data: bytes):
    return client.post("/analyses", files={"file": (name, data, "application/octet-stream")})


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_upload_valido(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "upload_dir", str(tmp_path))
    data = fake_apk()
    r = upload("app.apk", data)
    assert r.status_code == 202
    body = r.json()
    assert body["sha256"] == hashlib.sha256(data).hexdigest()
    assert body["size_bytes"] == len(data)
    assert body["status"] == "pending"
    assert (tmp_path / f"{body['id']}.apk").exists()


def test_rechaza_extension_incorrecta(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "upload_dir", str(tmp_path))
    assert upload("foto.png", fake_apk()).status_code == 400


def test_rechaza_contenido_que_no_es_apk(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "upload_dir", str(tmp_path))
    r = upload("falso.apk", b"esto es solo texto")
    assert r.status_code == 400
    assert list(tmp_path.iterdir()) == []  # no deja basura en disco


def test_rechaza_archivo_vacio(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "upload_dir", str(tmp_path))
    assert upload("vacio.apk", b"").status_code == 400


def test_rechaza_archivo_muy_grande(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "upload_dir", str(tmp_path))
    monkeypatch.setattr(settings, "max_upload_mb", 0)
    r = upload("grande.apk", fake_apk())
    assert r.status_code == 413
    assert list(tmp_path.iterdir()) == []