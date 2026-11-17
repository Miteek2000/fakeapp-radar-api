import hashlib
import zipfile

import pytest

from app.analysis.analyzer import InvalidApkError, analyze_apk
from tests.catalogo_prueba import CATALOGO
from tests.apk_factory import make_apk

BANCO_FALSO = [
    "READ_SMS",
    "BIND_ACCESSIBILITY_SERVICE",
    "SYSTEM_ALERT_WINDOW",
    "READ_CONTACTS",
    "ACCESS_FINE_LOCATION",
    "CAMERA",
]


def test_banco_falso_es_riesgo_alto(tmp_path):
    apk = make_apk(tmp_path / "banco.apk", package="com.banco.falso", app_label="Banca Segura",
                   version="2.3", permissions=BANCO_FALSO)
    r = analyze_apk(apk, CATALOGO)
    assert r.package_name == "com.banco.falso"
    assert r.app_name == "Banca Segura"
    assert r.version_name == "2.3"
    assert (r.min_sdk, r.target_sdk) == (21, 34)
    assert r.risk_score == 83  # 20 + 25 + 20 + 8 + 8 + 2
    assert r.risk_level == "alto"
    assert (r.counts.peligroso, r.counts.atencion, r.counts.normal) == (3, 2, 1)
    # los más graves salen primero
    assert r.permissions[0].android_name == "android.permission.BIND_ACCESSIBILITY_SERVICE"
    assert r.permissions[-1].android_name == "android.permission.CAMERA"
    assert all(p.known for p in r.permissions)


def test_app_inofensiva_es_riesgo_bajo(tmp_path):
    apk = make_apk(tmp_path / "linterna.apk", permissions=["INTERNET", "CAMERA"])
    r = analyze_apk(apk, CATALOGO)
    assert r.risk_score == 3
    assert r.risk_level == "bajo"
    assert r.counts.peligroso == 0


def test_riesgo_medio(tmp_path):
    apk = make_apk(tmp_path / "medio.apk", permissions=["READ_CONTACTS", "ACCESS_FINE_LOCATION",
                                                         "RECORD_AUDIO", "READ_CALL_LOG"])
    r = analyze_apk(apk, CATALOGO)
    assert r.risk_score == 36
    assert r.risk_level == "medio"


def test_el_puntaje_tiene_tope_de_100(tmp_path):
    todos = ["READ_SMS", "RECEIVE_SMS", "SEND_SMS", "BIND_ACCESSIBILITY_SERVICE",
             "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "BIND_DEVICE_ADMIN"]
    r = analyze_apk(make_apk(tmp_path / "malo.apk", permissions=todos), CATALOGO)
    assert r.risk_score == 100
    assert r.risk_level == "alto"


def test_permiso_desconocido_no_suma_puntos(tmp_path):
    r = analyze_apk(make_apk(tmp_path / "x.apk", permissions=["com.vendor.CUSTOM"]), CATALOGO)
    assert r.risk_score == 0
    assert r.permissions[0].known is False
    assert r.permissions[0].title == "CUSTOM"


def test_hashes_correctos(tmp_path):
    apk = make_apk(tmp_path / "h.apk", permissions=["CAMERA"])
    r = analyze_apk(apk, CATALOGO)
    data = apk.read_bytes()
    assert r.hashes.sha256 == hashlib.sha256(data).hexdigest()
    assert r.hashes.md5 == hashlib.md5(data).hexdigest()
    assert r.hashes.sha1 == hashlib.sha1(data).hexdigest()
    assert r.size_bytes == len(data)


def test_rechaza_archivo_que_no_es_zip(tmp_path):
    f = tmp_path / "falso.apk"
    f.write_bytes(b"esto no es un zip")
    with pytest.raises(InvalidApkError):
        analyze_apk(f, CATALOGO)


def test_rechaza_zip_sin_manifest(tmp_path):
    f = tmp_path / "sinmanifest.apk"
    with zipfile.ZipFile(f, "w") as z:
        z.writestr("otro.txt", "hola")
    with pytest.raises(InvalidApkError, match="AndroidManifest"):
        analyze_apk(f, CATALOGO)


def test_rechaza_manifest_corrupto(tmp_path):
    f = tmp_path / "corrupto.apk"
    with zipfile.ZipFile(f, "w") as z:
        z.writestr("AndroidManifest.xml", "esto no es un manifest binario")
    with pytest.raises(InvalidApkError):
        analyze_apk(f, CATALOGO)


def test_rechaza_zip_bomba(tmp_path):
    f = tmp_path / "bomba.apk"
    with zipfile.ZipFile(f, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", "x")
        z.writestr("relleno.bin", b"\x00" * (5 * 1024 * 1024))  # compresión enorme
    with pytest.raises(InvalidApkError, match="sospechosa"):
        analyze_apk(f, CATALOGO)


def test_rechaza_exceso_de_archivos(tmp_path):
    f = tmp_path / "muchos.apk"
    with zipfile.ZipFile(f, "w") as z:
        z.writestr("AndroidManifest.xml", "x")
        for i in range(5):
            z.writestr(f"a{i}.txt", str(i))
    with pytest.raises(InvalidApkError, match="demasiados"):
        analyze_apk(f, CATALOGO, max_entries=3)
