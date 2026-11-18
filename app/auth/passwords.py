"""Contraseñas con Argon2id (parámetros por defecto de argon2-cffi, perfil recomendado en RFC 9106)."""
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

_hasher = PasswordHasher()
# Hash de relleno: si el correo no existe igual gastamos el mismo tiempo, para no delatar qué correos están registrados.
_DUMMY_HASH = _hasher.hash("relleno-para-igualar-tiempos")

MIN_LENGTH = 10
MAX_LENGTH = 128


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(stored_hash or _DUMMY_HASH, password) and stored_hash is not None
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    return _hasher.check_needs_rehash(stored_hash)
