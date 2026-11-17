"""Cifrado AES-256-GCM de los reportes.

Formato guardado:  nonce (12 bytes) + texto cifrado + etiqueta de autenticación (16 bytes).
GCM, además de ocultar el contenido, detecta cualquier modificación. Usamos como
"datos asociados" el id del análisis: un reporte copiado a otra fila no se puede leer.
"""
import base64
import binascii
import json
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import settings

KEY_VERSION = 1  # para poder rotar la clave en el futuro
NONCE_BYTES = 12


def _key() -> bytes:
    try:
        key = base64.b64decode(settings.encryption_key, validate=True)
    except (binascii.Error, ValueError):
        key = b""
    if len(key) != 32:
        raise RuntimeError("ENCRYPTION_KEY debe ser una clave de 32 bytes codificada en base64")
    return key


def encrypt_json(data: dict[str, Any], aad: str) -> bytes:
    nonce = os.urandom(NONCE_BYTES)  # un nonce nuevo en cada cifrado: nunca se repite
    plain = json.dumps(data, ensure_ascii=False).encode("utf-8")
    return nonce + AESGCM(_key()).encrypt(nonce, plain, aad.encode("utf-8"))


def decrypt_json(blob: bytes, aad: str) -> dict[str, Any]:
    """Lanza cryptography.exceptions.InvalidTag si el dato fue alterado o la clave no es la correcta."""
    nonce, ciphertext = blob[:NONCE_BYTES], blob[NONCE_BYTES:]
    plain = AESGCM(_key()).decrypt(nonce, ciphertext, aad.encode("utf-8"))
    return json.loads(plain.decode("utf-8"))
