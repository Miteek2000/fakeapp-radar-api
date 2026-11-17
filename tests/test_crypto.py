import base64
import uuid

import pytest
from cryptography.exceptions import InvalidTag

from app import crypto
from app.config import settings
from app.db import session_scope
from app.models import Analysis
from tests.apk_factory import make_apk
from tests.test_api import client, upload

REPORTE = {"package_name": "com.banco.falso", "risk_score": 83, "permissions": ["READ_SMS"]}


def test_cifra_y_descifra():
    blob = crypto.encrypt_json(REPORTE, "analysis:1")
    assert crypto.decrypt_json(blob, "analysis:1") == REPORTE


def test_el_texto_cifrado_no_contiene_el_contenido():
    blob = crypto.encrypt_json(REPORTE, "analysis:1")
    assert b"com.banco.falso" not in blob
    assert b"READ_SMS" not in blob


def test_cada_cifrado_usa_un_nonce_distinto():
    a = crypto.encrypt_json(REPORTE, "analysis:1")
    b = crypto.encrypt_json(REPORTE, "analysis:1")
    assert a[:12] != b[:12]
    assert a != b


def test_un_dato_alterado_se_detecta():
    blob = bytearray(crypto.encrypt_json(REPORTE, "analysis:1"))
    blob[20] ^= 0x01
    with pytest.raises(InvalidTag):
        crypto.decrypt_json(bytes(blob), "analysis:1")


def test_un_reporte_copiado_a_otro_analisis_no_se_puede_leer():
    blob = crypto.encrypt_json(REPORTE, "analysis:1")
    with pytest.raises(InvalidTag):
        crypto.decrypt_json(blob, "analysis:2")


def test_con_otra_clave_no_se_puede_leer(monkeypatch):
    blob = crypto.encrypt_json(REPORTE, "analysis:1")
    monkeypatch.setattr(settings, "encryption_key", base64.b64encode(b"x" * 32).decode())
    with pytest.raises(InvalidTag):
        crypto.decrypt_json(blob, "analysis:1")


@pytest.mark.parametrize("clave", ["", "no-es-base64!!", base64.b64encode(b"corta").decode()])
def test_rechaza_claves_invalidas(monkeypatch, clave):
    monkeypatch.setattr(settings, "encryption_key", clave)
    with pytest.raises(RuntimeError):
        crypto.encrypt_json(REPORTE, "analysis:1")


def test_en_la_base_el_reporte_va_cifrado_y_el_hash_no(tmp_path):
    apk = make_apk(tmp_path / "b.apk", package="com.banco.falso", permissions=["READ_SMS", "CAMERA"])
    body = upload("b.apk", apk.read_bytes()).json()

    with session_scope() as s:
        row = s.get(Analysis, uuid.UUID(body["id"]))
        assert row.status == "done"
        assert row.sha256 == body["sha256"]  # el hash se guarda sin cifrar
        assert row.risk_score == 22 and row.risk_level == "bajo"
        assert row.key_version == 1
        assert b"com.banco.falso" not in row.report_enc  # el contenido NO aparece en claro
        assert b"READ_SMS" not in row.report_enc

    # y la API sí lo devuelve descifrado
    assert client.get(f"/analyses/{body['id']}").json()["report"]["package_name"] == "com.banco.falso"
