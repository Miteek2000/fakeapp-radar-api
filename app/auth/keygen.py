"""Genera una clave RSA nueva para firmar tokens:  python -m app.auth.keygen
Imprime el valor para JWT_PRIVATE_KEY_B64 (ponlo en tu .env; no lo compartas ni lo subas a GitHub)."""
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_b64(bits: int = 3072) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return base64.b64encode(pem).decode()


if __name__ == "__main__":
    print(generate_b64())
