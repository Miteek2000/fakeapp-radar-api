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

log = logging.getLogger(__name__)


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
        store.save(analysis_id, AnalysisStatus.done, report=report.model_dump(mode="json"))
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
