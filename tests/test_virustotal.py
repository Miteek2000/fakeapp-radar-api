import io
import json
import urllib.error
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app import store
from app.config import settings
from app.db import session_scope
from app.main import app
from app.models import Analysis, VtCache
from app.vt import client as vt
from app.worker import vt_tasks
from tests.apk_factory import make_apk

SHA = "c" * 64
http = TestClient(app)


# ---------- cliente ----------

class FakeResp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


def respuesta(stats: dict) -> FakeResp:
    return FakeResp(json.dumps({"data": {"attributes": {"last_analysis_stats": stats}}}).encode())


def http_error(code: int):
    return urllib.error.HTTPError("https://x", code, "err", {}, io.BytesIO(b""))


def test_cliente_interpreta_la_respuesta(monkeypatch):
    visto = {}
    def falso(req, timeout):
        visto["url"], visto["clave"] = req.full_url, req.get_header("X-apikey")
        return respuesta({"malicious": 5, "suspicious": 2, "undetected": 60, "harmless": 3, "timeout": 1})
    monkeypatch.setattr(vt.urllib.request, "urlopen", falso)
    r = vt.lookup(SHA, "clave-de-prueba")
    assert r == vt.VtResult(found=True, malicious=7, total=70)  # el timeout no cuenta como veredicto
    assert visto["url"].endswith("/files/" + SHA) and visto["clave"] == "clave-de-prueba"


def test_cliente_404_significa_archivo_desconocido(monkeypatch):
    def falso(req, timeout): raise http_error(404)
    monkeypatch.setattr(vt.urllib.request, "urlopen", falso)
    assert vt.lookup(SHA, "k") == vt.VtResult(found=False)


def test_cliente_429_y_otros_errores(monkeypatch):
    for codigo, excepcion in [(429, vt.VtRateLimited), (401, vt.VtUnavailable), (500, vt.VtUnavailable)]:
        monkeypatch.setattr(vt.urllib.request, "urlopen", lambda req, timeout, c=codigo: (_ for _ in ()).throw(http_error(c)))
        with pytest.raises(excepcion):
            vt.lookup(SHA, "k")


def test_cliente_sin_red_o_respuesta_rara(monkeypatch):
    monkeypatch.setattr(vt.urllib.request, "urlopen", lambda req, timeout: (_ for _ in ()).throw(urllib.error.URLError("sin red")))
    with pytest.raises(vt.VtUnavailable):
        vt.lookup(SHA, "k")
    monkeypatch.setattr(vt.urllib.request, "urlopen", lambda req, timeout: FakeResp(b'{"data": {}}'))
    with pytest.raises(vt.VtUnavailable):
        vt.lookup(SHA, "k")


def test_cliente_sin_clave_no_llama_a_nadie(monkeypatch):
    monkeypatch.setattr(vt.urllib.request, "urlopen", lambda *a, **k: pytest.fail("no debía hacer la llamada"))
    with pytest.raises(vt.VtUnavailable):
        vt.lookup(SHA, "")


@pytest.mark.parametrize("malo", ["../../etc/passwd", "a" * 63, "G" * 64, "a" * 64 + "/x", ""])
def test_cliente_rechaza_hashes_que_no_son_hashes(malo, monkeypatch):
    monkeypatch.setattr(vt.urllib.request, "urlopen", lambda *a, **k: pytest.fail("no debía hacer la llamada"))
    with pytest.raises(ValueError):
        vt.lookup(malo, "k")


# ---------- tarea + caché ----------

def nuevo_analisis() -> str:
    uid = uuid.uuid4()
    store.create(uid, SHA, 10)
    store.set_vt_pending(uid)
    return str(uid)


def vt_de(uid):
    return store.load(uid)["virustotal"]


def test_tarea_guarda_resultado_y_llena_la_cache(monkeypatch):
    llamadas = []
    monkeypatch.setattr(vt, "lookup", lambda sha, key: llamadas.append(sha) or vt.VtResult(True, 3, 70))
    uid = nuevo_analisis()
    vt_tasks.vt_lookup_task.apply(args=[uid, SHA]).get()
    d = vt_de(uid)
    assert (d["status"], d["malicious"], d["total"]) == ("found", 3, 70)
    assert d["url"] == f"https://www.virustotal.com/gui/file/{SHA}"
    # segundo análisis del mismo archivo: sale de la caché, sin llamar a VirusTotal
    uid2 = nuevo_analisis()
    vt_tasks.vt_lookup_task.apply(args=[uid2, SHA]).get()
    assert len(llamadas) == 1 and vt_de(uid2)["malicious"] == 3


def test_cache_vencida_se_vuelve_a_consultar(monkeypatch):
    monkeypatch.setattr(vt, "lookup", lambda sha, key: vt.VtResult(True, 1, 70))
    uid = nuevo_analisis(); vt_tasks.vt_lookup_task.apply(args=[uid, SHA]).get()
    with session_scope() as s:
        s.execute(update(VtCache).values(checked_at=datetime.now(timezone.utc) - timedelta(hours=settings.vt_cache_hours + 1)))
    assert store.vt_cache_get(SHA) is None


def test_archivo_desconocido_queda_como_not_found(monkeypatch):
    monkeypatch.setattr(vt, "lookup", lambda sha, key: vt.VtResult(False))
    uid = nuevo_analisis(); vt_tasks.vt_lookup_task.apply(args=[uid, SHA]).get()
    assert vt_de(uid)["status"] == "not_found" and vt_de(uid)["malicious"] is None


def test_si_no_esta_disponible_no_se_guarda_en_cache(monkeypatch):
    def falla(sha, key): raise vt.VtUnavailable("caído")
    monkeypatch.setattr(vt, "lookup", falla)
    uid = nuevo_analisis(); vt_tasks.vt_lookup_task.apply(args=[uid, SHA]).get()
    assert vt_de(uid)["status"] == "unavailable"
    with session_scope() as s:
        assert s.scalars(select(VtCache)).all() == []


class Reintento(Exception):
    pass


def sin_cuota(monkeypatch):
    def falla(sha, key): raise vt.VtRateLimited()
    monkeypatch.setattr(vt, "lookup", falla)
    pedidos = []
    def retry(**kw):
        pedidos.append(kw["countdown"])
        raise Reintento()
    monkeypatch.setattr(vt_tasks.vt_lookup_task, "retry", retry)
    return pedidos


def test_sin_cuota_pide_reintentar_despues_de_que_se_renueve(monkeypatch):
    pedidos = sin_cuota(monkeypatch)
    uid = nuevo_analisis()
    res = vt_tasks.vt_lookup_task.apply(args=[uid, SHA], retries=0)
    assert isinstance(res.result, Reintento) and pedidos == [vt_tasks.RETRY_SECONDS]
    assert vt_de(uid)["status"] == "pending"  # sigue esperando


def test_sin_cuota_y_sin_reintentos_marca_no_disponible(monkeypatch):
    pedidos = sin_cuota(monkeypatch)
    uid = nuevo_analisis()
    vt_tasks.vt_lookup_task.apply(args=[uid, SHA], retries=vt_tasks.MAX_RETRIES).get()
    assert pedidos == [] and vt_de(uid)["status"] == "unavailable"


def test_pending_viejo_se_muestra_como_no_disponible():
    uid = nuevo_analisis()
    assert vt_de(uid)["status"] == "pending"
    with session_scope() as s:
        s.execute(update(Analysis).values(updated_at=datetime.now(timezone.utc) - timedelta(minutes=settings.vt_pending_max_minutes + 1)))
    assert vt_de(uid)["status"] == "unavailable"


# ---------- de punta a punta por la API ----------

def subir(tmp_path):
    apk = make_apk(tmp_path / "a.apk", permissions=["android.permission.INTERNET"])
    r = http.post("/analyses", files={"file": ("a.apk", apk.read_bytes(), "application/octet-stream")})
    return http.get(f"/analyses/{r.json()['id']}").json()


def test_la_api_devuelve_la_reputacion(tmp_path, monkeypatch):
    monkeypatch.setattr(vt, "lookup", lambda sha, key: vt.VtResult(True, 9, 72))
    data = subir(tmp_path)
    assert data["status"] == "done"
    assert data["virustotal"]["status"] == "found" and data["virustotal"]["malicious"] == 9 and data["virustotal"]["total"] == 72
    assert data["virustotal"]["url"].startswith("https://www.virustotal.com/gui/file/")


def test_el_analisis_funciona_aunque_virustotal_falle(tmp_path, monkeypatch):
    def falla(sha, key): raise vt.VtUnavailable("caído")
    monkeypatch.setattr(vt, "lookup", falla)
    data = subir(tmp_path)
    assert data["status"] == "done" and data["report"]["risk_score"] is not None
    assert data["virustotal"]["status"] == "unavailable"


def test_el_analisis_funciona_aunque_no_se_pueda_encolar_la_consulta(tmp_path, monkeypatch):
    def cola_caida(*a, **k): raise ConnectionError("redis caído")
    monkeypatch.setattr(vt_tasks.vt_lookup_task, "apply_async", cola_caida)
    data = subir(tmp_path)
    assert data["status"] == "done" and data["virustotal"]["status"] == "unavailable"


def test_a_virustotal_solo_viaja_el_hash(tmp_path, monkeypatch):
    enviados = []
    monkeypatch.setattr(vt, "lookup", lambda *args: enviados.append(args) or vt.VtResult(False))
    data = subir(tmp_path)
    assert len(enviados) == 1 and enviados[0][0] == data["report"]["hashes"]["sha256"]


def test_virustotal_queda_pendiente_antes_de_que_el_analisis_figure_como_terminado(tmp_path, monkeypatch):
    """Nunca debe existir un momento con status 'done' y virustotal en None."""
    vistos = []
    original = store.save
    def espia(analysis_id, status, **kw):
        if getattr(status, "value", status) == "done":
            vistos.append(store.load(analysis_id)["virustotal"])
        return original(analysis_id, status, **kw)
    monkeypatch.setattr(store, "save", espia)
    monkeypatch.setattr(vt, "lookup", lambda sha, key: vt.VtResult(False))
    subir(tmp_path)
    assert vistos and vistos[0] is not None and vistos[0]["status"] == "pending"
