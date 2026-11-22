"""Archivo de PRÁCTICA para probar la consulta WeakHashVariants.ql.
No forma parte de la aplicación (no se copia a la imagen Docker).
Las líneas marcadas MALO deben aparecer en los resultados; las marcadas BIEN, no."""
import hashlib
from hashlib import md5 as huella_md5
from cryptography.hazmat.primitives import hashes


def malo_directo(data: bytes):
    return hashlib.md5(data).hexdigest()  # MALO: variante 1


def malo_sha1(data: bytes):
    return hashlib.sha1(data).hexdigest()  # MALO: variante 1


def malo_alias(data: bytes):
    return huella_md5(data).hexdigest()  # MALO: variante 1 con alias


def malo_por_nombre(data: bytes):
    return hashlib.new("MD5", data).hexdigest()  # MALO: variante 2


def malo_explicito(data: bytes):
    return hashlib.md5(data, usedforsecurity=True).hexdigest()  # MALO: dice que sí es de seguridad


def malo_cryptography():
    return hashes.MD5()  # MALO: variante 3


def bien_referencia(data: bytes):
    return hashlib.md5(data, usedforsecurity=False).hexdigest()  # BIEN: dato de referencia


def bien_sha256(data: bytes):
    return hashlib.sha256(data).hexdigest()  # BIEN: algoritmo fuerte
