import logging
from pathlib import Path
from uuid import UUID

from celery.exceptions import SoftTimeLimitExceeded

from app import store
from app.analysis.catalog import load_catalog
from app.analysis.analyzer import InvalidApkError, analyze_apk
from app.config import settings
from app.db import session_scope
from app.schemas import AnalysisStatus
from app.worker.celery_app import celery_app
from app.worker.vt_tasks import vt_lookup_task

log = logging.getLogger(__name__)


def _mark_vt_pending(analysis_id: str) -> bool:
    """Se marca ANTES de terminar el análisis, así quien consulta nunca ve 'listo' sin saber qué pasa con VirusTotal."""
    try:
        store.set_vt_pending(analysis_id)
        return True
    except Exception:
        log.exception("No se pudo marcar VirusTotal como pendiente (%s)", analysis_id)
        return False


def _ask_virustotal(analysis_id: str, sha256: str) -> None:
    """Pide la reputación a VirusTotal en segundo plano. Si falla, el análisis sigue siendo válido."""
    try:
        vt_lookup_task.apply_async(args=[analysis_id, sha256], expires=settings.vt_pending_max_minutes * 60)
    except Exception:
        log.exception("No se pudo encolar la consulta a VirusTotal (%s)", analysis_id)
        try:
            store.save_vt(analysis_id, "unavailable")
        except Exception:
            log.exception("Tampoco se pudo marcar VirusTotal como no disponible (%s)", analysis_id)


@celery_app.task(name="analyze_apk")
def analyze_apk_task(analysis_id: str) -> None:
    # Validamos que sea un UUID antes de armar la ruta del archivo.
    analysis_id = str(UUID(analysis_id))
    path = Path(settings.upload_dir) / f"{analysis_id}.apk"

    store.save(analysis_id, AnalysisStatus.running)
    try:
        with session_scope() as session:
            catalog = load_catalog(session)
        report = analyze_apk(path, catalog)
        vt_marked = _mark_vt_pending(analysis_id)
        store.save(analysis_id, AnalysisStatus.done, report=report.model_dump(mode="json"))
        if vt_marked:
            _ask_virustotal(analysis_id, report.hashes.sha256)
    except InvalidApkError as exc:
        store.save(analysis_id, AnalysisStatus.failed, error=str(exc))
    except SoftTimeLimitExceeded:
        store.save(analysis_id, AnalysisStatus.failed, error="El análisis tardó demasiado y se canceló")
    except Exception:
        # El detalle técnico va al log del servidor, no al usuario.
        log.exception("Error inesperado analizando %s", analysis_id)
        store.save(analysis_id, AnalysisStatus.failed, error="Ocurrió un error inesperado al analizar el archivo")
    finally:
        # Ya tenemos el reporte y el hash: el APK no se necesita más en disco.
        path.unlink(missing_ok=True)
