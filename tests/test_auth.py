import base64
import time
import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.auth import passwords, service, tokens
from app.config import settings
from app.db import session_scope
from app.main import app
from app.models import RefreshToken, User
from app.ratelimit import limiter
from tests.apk_factory import make_apk

PASS = "una-clave-larga-123"
ORIGIN = {"Origin": "http://localhost:3000"}


def nuevo_cliente() -> TestClient:
    return TestClient(app)  # cada cliente tiene su propio "navegador" (cookies propias)


def registrar(c: TestClient, email="mayte@ejemplo.com", password=PASS):
    return c.post("/auth/register", json={"email": email, "password": password})


def entrar(c: TestClient, email="mayte@ejemplo.com", password=PASS):
    return c.post("/auth/login", json={"email": email, "password": password})


def cabecera(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def sesion(c: TestClient, email="mayte@ejemplo.com") -> str:
    registrar(c, email)
    r = entrar(c, email)
    assert r.status_code == 200
    return r.json()["access_token"]


# ---------- contraseñas ----------

def test_la_contrasena_se_guarda_con_argon2id():
    h = passwords.hash_password(PASS)
    assert h.startswith("$argon2id$") and PASS not in h
    assert passwords.verify_password(h, PASS) and not passwords.verify_password(h, PASS + "x")


def test_verificar_sin_usuario_siempre_falla_pero_gasta_tiempo_de_hash():
    assert passwords.verify_password(None, "relleno-para-igualar-tiempos") is False


# ---------- registro ----------

def test_registro_normaliza_el_correo_y_no_devuelve_la_contrasena():
    c = nuevo_cliente()
    r = registrar(c, "  Mayte@Ejemplo.COM ")
    assert r.status_code == 201 and r.json()["email"] == "mayte@ejemplo.com"
    assert "password" not in r.text and "hash" not in r.text
    with session_scope() as s:
        u = s.scalar(select(User))
        assert u.email == "mayte@ejemplo.com" and u.password_hash.startswith("$argon2id$")


def test_no_se_puede_registrar_dos_veces_el_mismo_correo_ni_cambiando_mayusculas():
    c = nuevo_cliente()
    assert registrar(c).status_code == 201
    assert registrar(c, "MAYTE@ejemplo.com").status_code == 409


@pytest.mark.parametrize("email,password,fragmento", [
    ("no-es-correo", PASS, "correo"),
    ("a@b", PASS, "correo"),
    ("mayte@ejemplo.com", "corta", "al menos 10"),
    ("mayte@ejemplo.com", "x" * 129, "no puede pasar"),
    ("mayte@ejemplo.com", "mayte@ejemplo.com", "igual a tu correo"),
])
def test_registro_rechaza_datos_invalidos(email, password, fragmento):
    r = registrar(nuevo_cliente(), email, password)
    assert r.status_code == 422 and fragmento in r.json()["detail"]


# ---------- login ----------

def test_login_devuelve_token_y_pone_la_cookie_de_refresh_bien_configurada():
    c = nuevo_cliente(); registrar(c)
    r = entrar(c)
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer" and body["expires_in"] == 15 * 60 and body["user"]["email"] == "mayte@ejemplo.com"
    cookie = r.headers["set-cookie"].lower()
    assert "refresh_token=" in cookie and "httponly" in cookie and "samesite=strict" in cookie
    assert "secure" not in cookie.replace("samesite", "")  # en desarrollo (http) no se marca Secure
    assert r.headers["cache-control"] == "no-store"
    assert "refresh_token" not in body  # el refresh NO viaja en el cuerpo, solo en la cookie


def test_cookie_secure_cuando_se_activa(monkeypatch):
    monkeypatch.setattr(settings, "cookie_secure", True)
    c = nuevo_cliente(); registrar(c)
    assert "secure" in entrar(c).headers["set-cookie"].lower().replace("samesite", "")


def test_login_con_datos_malos_da_el_mismo_error_exista_o_no_el_correo():
    c = nuevo_cliente(); registrar(c)
    a = entrar(c, password="otra-clave-larga-1")
    b = entrar(c, email="nadie@ejemplo.com")
    assert a.status_code == b.status_code == 401 and a.json() == b.json()
    assert "refresh_token" not in a.headers.get("set-cookie", "")


def test_cuenta_desactivada_no_puede_entrar():
    c = nuevo_cliente(); registrar(c)
    with session_scope() as s:
        s.execute(update(User).values(is_active=False))
    assert entrar(c).status_code == 401


# ---------- token de acceso (JWT) ----------

def llave_publica():
    return tokens._private_key().public_key()


def test_el_token_es_rs256_con_vida_de_15_minutos_y_sin_datos_sensibles():
    c = nuevo_cliente(); tok = sesion(c)
    header = jwt.get_unverified_header(tok)
    datos = jwt.decode(tok, llave_publica(), algorithms=["RS256"], audience=settings.jwt_audience)
    assert header["alg"] == "RS256"
    assert datos["exp"] - datos["iat"] == 15 * 60
    assert set(datos) == {"sub", "iss", "aud", "iat", "exp", "jti", "typ"}  # sin correo ni contraseña


def forjar(claims_extra=None, key=None, alg="RS256", quitar=()):
    ahora = datetime.now(timezone.utc)
    claims = {"sub": str(uuid.uuid4()), "iss": settings.jwt_issuer, "aud": settings.jwt_audience,
              "iat": ahora, "exp": ahora + timedelta(minutes=5), "jti": "x", "typ": "access"}
    claims.update(claims_extra or {})
    for q in quitar:
        claims.pop(q)
    return jwt.encode(claims, key or tokens._private_key(), algorithm=alg)


def usuario_real() -> uuid.UUID:
    with session_scope() as s:
        return s.scalar(select(User.id))


def test_rutas_protegidas_exigen_token():
    c = nuevo_cliente()
    assert c.get("/auth/me").status_code == 401
    assert c.get("/analyses").status_code == 401
    assert c.get("/auth/me", headers=cabecera("basura")).status_code == 401


def test_token_valido_da_acceso():
    c = nuevo_cliente(); tok = sesion(c)
    assert c.get("/auth/me", headers=cabecera(tok)).json()["email"] == "mayte@ejemplo.com"


@pytest.mark.parametrize("ataque", ["expirado", "otra_clave", "alg_none", "hs256_con_clave_publica", "otro_emisor",
                                   "otra_audiencia", "tipo_refresh", "sin_exp", "alterado"])
def test_ataques_a_jwt_son_rechazados(ataque):
    c = nuevo_cliente(); tok = sesion(c)
    uid = str(usuario_real())
    ahora = datetime.now(timezone.utc)
    if ataque == "expirado":
        malo = forjar({"sub": uid, "iat": ahora - timedelta(hours=1), "exp": ahora - timedelta(minutes=1)})
    elif ataque == "otra_clave":
        malo = forjar({"sub": uid}, key=rsa.generate_private_key(65537, 2048))
    elif ataque == "alg_none":
        malo = jwt.encode({"sub": uid, "iss": settings.jwt_issuer, "aud": settings.jwt_audience,
                           "iat": ahora, "exp": ahora + timedelta(minutes=5), "typ": "access"}, key=None, algorithm="none")
    elif ataque == "hs256_con_clave_publica":  # el clásico: firmar con HMAC usando la clave pública como secreto
        pem = llave_publica().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        claims = {"sub": uid, "iss": settings.jwt_issuer, "aud": settings.jwt_audience,
                  "iat": int(ahora.timestamp()), "exp": int((ahora + timedelta(minutes=5)).timestamp()), "typ": "access"}
        import hashlib, hmac, json
        b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
        cuerpo = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()) + "." + b64(json.dumps(claims).encode())
        malo = cuerpo + "." + b64(hmac.new(pem, cuerpo.encode(), hashlib.sha256).digest())
    elif ataque == "otro_emisor":
        malo = forjar({"sub": uid, "iss": "otro"})
    elif ataque == "otra_audiencia":
        malo = forjar({"sub": uid, "aud": "otra-app"})
    elif ataque == "tipo_refresh":
        malo = forjar({"sub": uid, "typ": "refresh"})
    elif ataque == "sin_exp":
        malo = forjar({"sub": uid}, quitar=("exp",))
    else:  # alterado: se cambia el usuario sin volver a firmar
        cab, cuerpo, firma = tok.split(".")
        falso = base64.urlsafe_b64encode(b'{"sub":"%s"}' % uid.encode()).rstrip(b"=").decode()
        malo = f"{cab}.{falso}.{firma}"
    assert c.get("/auth/me", headers=cabecera(malo)).status_code == 401


def test_token_de_usuario_borrado_deja_de_servir_al_instante():
    c = nuevo_cliente(); tok = sesion(c)
    with session_scope() as s:
        s.delete(s.scalar(select(User)))
    assert c.get("/auth/me", headers=cabecera(tok)).status_code == 401


def test_sin_clave_configurada_el_login_responde_503_y_no_se_cae(monkeypatch):
    c = nuevo_cliente(); registrar(c)
    monkeypatch.setattr(settings, "jwt_private_key_b64", "")
    assert entrar(c).status_code == 503


def test_clave_rsa_debil_o_mal_formada_se_rechaza(monkeypatch):
    c = nuevo_cliente(); registrar(c)
    debil = rsa.generate_private_key(65537, 1024).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    for valor in (base64.b64encode(debil).decode(), "no-es-base64-ni-pem"):
        monkeypatch.setattr(settings, "jwt_private_key_b64", valor)
        assert entrar(c).status_code == 503


# ---------- refresh: rotación, robo, logout ----------

def cookie_de(c: TestClient) -> str:
    return c.cookies.get("refresh_token")


def test_refresh_entrega_token_nuevo_y_rota_la_cookie():
    c = nuevo_cliente(); sesion(c)
    antes = cookie_de(c)
    r = c.post("/auth/refresh", headers=ORIGIN)
    assert r.status_code == 200 and r.json()["access_token"]
    assert cookie_de(c) and cookie_de(c) != antes
    # solo se guarda el hash, nunca el token
    with session_scope() as s:
        hashes = s.scalars(select(RefreshToken.token_hash)).all()
    assert antes not in hashes and cookie_de(c) not in hashes and all(len(h) == 64 for h in hashes)


def test_refresh_sin_cookie_o_inventado_da_401():
    c = nuevo_cliente()
    assert c.post("/auth/refresh").status_code == 401
    c.cookies.set("refresh_token", "inventado")
    assert c.post("/auth/refresh").status_code == 401


def test_reutilizar_un_refresh_viejo_cierra_toda_la_sesion(monkeypatch):
    """Si alguien roba un refresh y lo usa después de que el dueño ya lo rotó, se revoca la familia completa."""
    monkeypatch.setattr(settings, "refresh_reuse_grace_seconds", 0)
    c = nuevo_cliente(); sesion(c)
    robado = cookie_de(c)
    assert c.post("/auth/refresh").status_code == 200          # el dueño renueva
    vigente = cookie_de(c)
    time.sleep(0.01)
    atacante = nuevo_cliente(); atacante.cookies.set("refresh_token", robado)
    assert atacante.post("/auth/refresh").status_code == 401   # reutilización: se detecta
    c.cookies.set("refresh_token", vigente)
    assert c.post("/auth/refresh").status_code == 401          # el token legítimo también quedó revocado


def test_dos_pestanas_refrescando_a_la_vez_no_cierran_la_sesion():
    c = nuevo_cliente(); sesion(c)
    viejo = cookie_de(c)
    assert c.post("/auth/refresh").status_code == 200
    nuevo = cookie_de(c)
    otra = nuevo_cliente(); otra.cookies.set("refresh_token", viejo)   # la otra pestaña llegó un instante tarde
    assert otra.post("/auth/refresh").status_code == 409
    c.cookies.set("refresh_token", nuevo)
    assert c.post("/auth/refresh").status_code == 200                  # la sesión sigue viva


def test_refresh_vencido_se_rechaza():
    c = nuevo_cliente(); sesion(c)
    with session_scope() as s:
        s.execute(update(RefreshToken).values(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)))
    assert c.post("/auth/refresh").status_code == 401


def test_refresh_de_cuenta_desactivada_se_rechaza():
    c = nuevo_cliente(); sesion(c)
    with session_scope() as s:
        s.execute(update(User).values(is_active=False))
    assert c.post("/auth/refresh").status_code == 401


def test_logout_revoca_la_sesion_y_borra_la_cookie():
    c = nuevo_cliente(); sesion(c)
    guardada = cookie_de(c)
    r = c.post("/auth/logout", headers=ORIGIN)
    assert r.status_code == 204 and "max-age=0" in r.headers["set-cookie"].lower().replace(" ", "")
    c.cookies.set("refresh_token", guardada)
    assert c.post("/auth/refresh").status_code == 401   # aunque alguien conserve la cookie, ya no sirve


def test_logout_sin_sesion_no_falla():
    assert nuevo_cliente().post("/auth/logout").status_code == 204


def test_csrf_las_rutas_con_cookie_rechazan_origenes_ajenos():
    c = nuevo_cliente(); sesion(c)
    assert c.post("/auth/refresh", headers={"Origin": "https://sitio-malo.com"}).status_code == 403
    assert c.post("/auth/logout", headers={"Origin": "https://sitio-malo.com"}).status_code == 403
    assert c.post("/auth/refresh", headers={"Origin": "http://localhost:3000"}).status_code == 200
    assert c.post("/auth/refresh").status_code == 200   # sin Origin (curl, apps): permitido


def test_la_limpieza_borra_refresh_tokens_vencidos():
    c = nuevo_cliente(); sesion(c)
    with session_scope() as s:
        s.execute(update(RefreshToken).values(expires_at=datetime.now(timezone.utc) - timedelta(days=2)))
    assert service.purge_old_refresh_tokens() == 1


# ---------- análisis con dueño ----------

def subir(c: TestClient, tmp_path, token=None, nombre="a.apk"):
    apk = make_apk(tmp_path / nombre, permissions=["android.permission.INTERNET"])
    h = cabecera(token) if token else {}
    return c.post("/analyses", files={"file": (nombre, apk.read_bytes(), "application/octet-stream")}, headers=h)


def test_el_analisis_anonimo_sigue_funcionando_como_antes(tmp_path):
    c = nuevo_cliente()
    r = subir(c, tmp_path)
    assert r.status_code == 202
    assert c.get(f"/analyses/{r.json()['id']}").json()["status"] == "done"


def test_un_analisis_con_cuenta_solo_lo_ve_su_dueno(tmp_path):
    ana, beto, anonimo = nuevo_cliente(), nuevo_cliente(), nuevo_cliente()
    t_ana, t_beto = sesion(ana, "ana@ejemplo.com"), sesion(beto, "beto@ejemplo.com")
    aid = subir(ana, tmp_path, t_ana).json()["id"]
    assert ana.get(f"/analyses/{aid}", headers=cabecera(t_ana)).status_code == 200
    assert beto.get(f"/analyses/{aid}", headers=cabecera(t_beto)).status_code == 404   # ni se sabe que existe
    assert anonimo.get(f"/analyses/{aid}").status_code == 404
    assert anonimo.get(f"/analyses/{uuid.uuid4()}").json() == beto.get(f"/analyses/{aid}", headers=cabecera(t_beto)).json()


def test_el_dueno_no_puede_ser_elegido_por_el_cliente(tmp_path):
    ana, beto = nuevo_cliente(), nuevo_cliente()
    sesion(ana, "ana@ejemplo.com"); t_beto = sesion(beto, "beto@ejemplo.com")
    apk = make_apk(tmp_path / "x.apk", permissions=[])
    r = beto.post("/analyses?user_id=" + str(usuario_real()), data={"user_id": str(usuario_real())},
                  files={"file": ("x.apk", apk.read_bytes(), "application/octet-stream")}, headers=cabecera(t_beto))
    with session_scope() as s:
        from app.models import Analysis
        dueno = s.scalar(select(Analysis.user_id).where(Analysis.id == uuid.UUID(r.json()["id"])))
        beto_id = s.scalar(select(User.id).where(User.email == "beto@ejemplo.com"))
    assert dueno == beto_id


def test_token_invalido_al_subir_se_rechaza_en_vez_de_tratarlo_como_anonimo(tmp_path):
    assert subir(nuevo_cliente(), tmp_path, "token-falso").status_code == 401


def test_historial_solo_muestra_los_propios_y_no_incluye_el_reporte(tmp_path):
    ana, beto = nuevo_cliente(), nuevo_cliente()
    t_ana, t_beto = sesion(ana, "ana@ejemplo.com"), sesion(beto, "beto@ejemplo.com")
    subir(ana, tmp_path, t_ana, "1.apk"); subir(ana, tmp_path, t_ana, "2.apk"); subir(beto, tmp_path, t_beto, "3.apk")
    subir(nuevo_cliente(), tmp_path, None, "4.apk")  # anónimo: no sale en ningún historial
    lista = ana.get("/analyses", headers=cabecera(t_ana)).json()
    assert len(lista["items"]) == 2 and lista["limit"] == 20
    assert all(set(i) == {"id", "status", "sha256", "size_bytes", "risk_score", "risk_level", "created_at", "finished_at"} for i in lista["items"])
    assert len(beto.get("/analyses", headers=cabecera(t_beto)).json()["items"]) == 1
    assert len(ana.get("/analyses?limit=1", headers=cabecera(t_ana)).json()["items"]) == 1
    assert ana.get("/analyses?limit=1000", headers=cabecera(t_ana)).status_code == 422


def test_si_se_exige_cuenta_el_anonimo_no_puede_subir(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "allow_anonymous", False)
    c = nuevo_cliente()
    assert subir(c, tmp_path).status_code == 401
    assert subir(c, tmp_path, sesion(c)).status_code == 202


# ---------- límite de peticiones ----------

@pytest.fixture
def con_limite():
    limiter.reset(); limiter.enabled = True
    yield
    limiter.enabled = False; limiter.reset()


def test_login_se_limita_a_5_por_minuto_por_ip(con_limite):
    c = nuevo_cliente()
    codigos = [c.post("/auth/login", json={"email": "x@ejemplo.com", "password": "mala-clave-larga"}).status_code for _ in range(7)]
    assert codigos[:5] == [401] * 5 and codigos[5:] == [429, 429]


def test_respuesta_429_en_espanol_con_retry_after(con_limite):
    c = nuevo_cliente()
    for _ in range(5):
        c.post("/auth/login", json={"email": "x@ejemplo.com", "password": "mala-clave-larga"})
    r = c.post("/auth/login", json={"email": "x@ejemplo.com", "password": "mala-clave-larga"})
    assert r.status_code == 429 and "demasiadas solicitudes" in r.json()["detail"].lower()
    assert "retry-after" in {k.lower() for k in r.headers}


def test_subir_archivos_se_limita_a_5_por_minuto(con_limite, tmp_path):
    c = nuevo_cliente()
    codigos = [subir(c, tmp_path, nombre=f"{i}.apk").status_code for i in range(6)]
    assert codigos == [202] * 5 + [429]


def test_cada_ip_tiene_su_propio_contador(con_limite, monkeypatch):
    monkeypatch.setattr(settings, "trust_proxy_headers", True)
    c = nuevo_cliente()
    datos = {"email": "x@ejemplo.com", "password": "mala-clave-larga"}
    for _ in range(5):
        c.post("/auth/login", json=datos, headers={"X-Forwarded-For": "1.1.1.1"})
    assert c.post("/auth/login", json=datos, headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 429
    assert c.post("/auth/login", json=datos, headers={"X-Forwarded-For": "2.2.2.2"}).status_code == 401


def test_x_forwarded_for_se_ignora_si_no_hay_proxy_de_confianza(con_limite):
    """Si no, cualquiera se saltaría el límite cambiando esa cabecera en cada petición."""
    c = nuevo_cliente()
    datos = {"email": "x@ejemplo.com", "password": "mala-clave-larga"}
    codigos = [c.post("/auth/login", json=datos, headers={"X-Forwarded-For": f"9.9.9.{i}"}).status_code for i in range(6)]
    assert codigos[-1] == 429
