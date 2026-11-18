"""Token de acceso (JWT RS256, vida corta) y token de refresco (aleatorio, se guarda su hash)."""
import base64
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from functools import lru_cache

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.config import settings

ALGORITHM = "RS256"  # fijo: nunca se acepta el algoritmo que declare el token


class AuthNotConfigured(RuntimeError):
    pass


class InvalidToken(Exception):
    pass


@lru_cache(maxsize=4)
def _load_private_key(b64: str) -> rsa.RSAPrivateKey:
    try:
        key = serialization.load_pem_private_key(base64.b64decode(b64, validate=True), password=None)
    except Exception as exc:  # noqa: BLE001 - cualquier fallo de formato significa lo mismo
        raise AuthNotConfigured("JWT_PRIVATE_KEY_B64 no es un PEM válido en base64") from exc
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise AuthNotConfigured("La clave JWT debe ser RSA de al menos 2048 bits")
    return key


def _private_key() -> rsa.RSAPrivateKey:
    if not settings.jwt_private_key_b64:
        raise AuthNotConfigured("Falta JWT_PRIVATE_KEY_B64")
    return _load_private_key(settings.jwt_private_key_b64)


def create_access_token(user_id: uuid.UUID) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": str(user_id),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_minutes),
        "jti": uuid.uuid4().hex,
        "typ": "access",
    }
    return jwt.encode(claims, _private_key(), algorithm=ALGORITHM)


def decode_access_token(token: str) -> uuid.UUID:
    """Devuelve el id del usuario o lanza InvalidToken (expirado, alterado, de otro emisor...)."""
    try:
        data = jwt.decode(
            token,
            _private_key().public_key(),
            algorithms=[ALGORITHM],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={"require": ["exp", "iat", "sub", "iss", "aud"]},
        )
        if data.get("typ") != "access":
            raise InvalidToken()
        return uuid.UUID(data["sub"])
    except AuthNotConfigured:
        raise
    except (jwt.PyJWTError, ValueError, KeyError) as exc:
        raise InvalidToken() from exc


def new_refresh_token() -> str:
    return secrets.token_urlsafe(32)


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
