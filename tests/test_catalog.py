from sqlalchemy import delete, update

from app.analysis.catalog import EmptyCatalogError, load_catalog
from app.db import session_scope
from app.models import PermissionCatalog
from tests.apk_factory import make_apk
from tests.catalogo_prueba import FILAS
import pytest

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def subir_y_consultar(tmp_path, permisos):
    apk = make_apk(tmp_path / "a.apk", permissions=permisos)
    r = client.post("/analyses", files={"file": ("a.apk", apk.read_bytes(), "application/octet-stream")})
    return client.get(f"/analyses/{r.json()['id']}").json()


def test_carga_el_catalogo_desde_la_base():
    with session_scope() as s:
        cat = load_catalog(s)
    assert len(cat) == len(FILAS)
    assert cat["android.permission.READ_SMS"].severity == "peligroso"


def test_catalogo_vacio_da_error_claro():
    with session_scope() as s:
        s.execute(delete(PermissionCatalog))
    with session_scope() as s:
        with pytest.raises(EmptyCatalogError, match="vacía"):
            load_catalog(s)


def test_analisis_con_catalogo_vacio_falla_sin_mostrar_detalles_tecnicos(tmp_path):
    with session_scope() as s:
        s.execute(delete(PermissionCatalog))
    data = subir_y_consultar(tmp_path, ["android.permission.READ_SMS"])
    assert data["status"] == "failed"
    assert "permission_catalog" not in data["error"]


def test_un_cambio_en_la_tabla_se_nota_sin_tocar_codigo(tmp_path):
    antes = subir_y_consultar(tmp_path, ["android.permission.CAMERA"])["report"]
    with session_scope() as s:
        s.execute(update(PermissionCatalog).where(PermissionCatalog.android_name == "android.permission.CAMERA").values(weight=40, severity="peligroso"))
    despues = subir_y_consultar(tmp_path, ["android.permission.CAMERA"])["report"]
    assert antes["risk_score"] == 2
    assert despues["risk_score"] == 40 and despues["permissions"][0]["severity"] == "peligroso"
