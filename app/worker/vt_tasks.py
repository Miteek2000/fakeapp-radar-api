"""Consulta de reputación en VirusTotal. Corre SOLO en el servicio vt-worker (cola `vt`).

Recibe únicamente el id del análisis y el SHA-256: no tiene acceso a los archivos ni a la clave de cifrado.
"""
import logging

from app import store
from app.config import settings
from app.vt import client
from app.worker.celery_app import celery_app

log = logging.getLogger(__name__)

MAX_RETRIES = 3
RETRY_SECONDS = 65  # la cuota gratuita es de 4 consultas por minuto


def resolve(sha256: str) -> dict:
    """Devuelve {status, malicious, total}. Usa la caché y solo consulta a VirusTotal si hace falta."""
    cached = store.vt_cache_get(sha256)
    if cached is not None:
        return cached
    result = client.lookup(sha256, settings.vt_api_key)
    if result.found:
        out = {"status": "found", "malicious": result.malicious, "total": result.total}
    else:
        out = {"status": "not_found", "malicious": None, "total": None}
    store.vt_cache_put(sha256, **out)
    return out


@celery_app.task(name="vt_lookup", bind=True, rate_limit="4/m", max_retries=MAX_RETRIES)
def vt_lookup_task(self, analysis_id: str, sha256: str) -> None:
    try:
        out = resolve(sha256)
    except client.VtRateLimited as exc:
        if self.request.retries >= MAX_RETRIES:
            log.warning("VirusTotal sigue sin cuota; se marca como no disponible (%s)", analysis_id)
            store.save_vt(analysis_id, "unavailable")
            return
        raise self.retry(exc=exc, countdown=RETRY_SECONDS)
    except client.VtUnavailable as exc:
        log.warning("VirusTotal no disponible: %s", exc)
        store.save_vt(analysis_id, "unavailable")
        return
    store.save_vt(analysis_id, **out)
