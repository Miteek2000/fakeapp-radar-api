"""Cliente mínimo de VirusTotal v3. Solo consulta por SHA-256: el archivo NUNCA se sube.

Documentación: https://docs.virustotal.com/reference/file-info
"""
import json
import urllib.error
import urllib.request
from dataclasses import dataclass

BASE_URL = "https://www.virustotal.com/api/v3/files/"
TIMEOUT_SECONDS = 15


class VtRateLimited(Exception):
    """VirusTotal respondió 429: se acabó la cuota por minuto o por día."""


class VtUnavailable(Exception):
    """No se pudo consultar (sin clave, sin red, clave rechazada o error del servicio)."""


@dataclass(frozen=True)
class VtResult:
    found: bool
    malicious: int | None = None
    total: int | None = None


def lookup(sha256: str, api_key: str) -> VtResult:
    if not api_key:
        raise VtUnavailable("Falta VT_API_KEY")
    if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
        raise ValueError("sha256 inválido")  # nunca armamos una URL con texto que no sea un hash

    req = urllib.request.Request(BASE_URL + sha256, headers={"x-apikey": api_key, "accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            body = json.load(resp)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return VtResult(found=False)  # VirusTotal nunca vio este archivo
        if exc.code == 429:
            raise VtRateLimited() from exc
        raise VtUnavailable(f"VirusTotal respondió {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise VtUnavailable("No se pudo contactar a VirusTotal") from exc

    try:
        stats = body["data"]["attributes"]["last_analysis_stats"]
        malicious = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
        total = sum(int(stats.get(k, 0)) for k in ("malicious", "suspicious", "undetected", "harmless"))
    except (KeyError, TypeError, ValueError) as exc:
        raise VtUnavailable("Respuesta inesperada de VirusTotal") from exc
    return VtResult(found=True, malicious=malicious, total=total)
