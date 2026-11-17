import hashlib
import logging
import uuid
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, File, HTTPException, UploadFile, status
from starlette.concurrency import run_in_threadpool

from app import store
from app.config import settings
from app.schemas import AnalysisCreated, AnalysisResult, AnalysisStatus
from app.worker.tasks import analyze_apk_task

log = logging.getLogger(__name__)
router = APIRouter(prefix="/analyses", tags=["analyses"])

CHUNK_SIZE = 1024 * 1024  # 1 MB
ZIP_MAGIC = b"PK\x03\x04"  # un APK es un archivo ZIP


def _enqueue(analysis_id: UUID, sha256: str, size: int) -> None:
    # Primero el registro (el worker lo va a actualizar) y luego la tarea.
    store.create(analysis_id, sha256, size)
    try:
        analyze_apk_task.delay(str(analysis_id))
    except Exception:
        store.discard(analysis_id)  # no dejamos un análisis "pending" que nadie va a procesar
        raise


@router.post("", response_model=AnalysisCreated, status_code=status.HTTP_202_ACCEPTED)
async def create_analysis(file: UploadFile = File(...)):
    if not (file.filename or "").lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="El archivo debe ser un .apk")

    max_bytes = settings.max_upload_mb * 1024 * 1024
    upload_dir = Path(settings.upload_dir)
    upload_dir.mkdir(parents=True, exist_ok=True)

    # Nunca usamos el nombre que manda el usuario para guardar el archivo.
    analysis_id = uuid.uuid4()
    dest = upload_dir / f"{analysis_id}.apk"

    sha256 = hashlib.sha256()
    size = 0
    first_chunk = True

    try:
        with dest.open("wb") as out:
            while chunk := await file.read(CHUNK_SIZE):
                if first_chunk:
                    if not chunk.startswith(ZIP_MAGIC):
                        raise HTTPException(status_code=400, detail="El archivo no parece un APK válido")
                    first_chunk = False
                size += len(chunk)
                if size > max_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail=f"El archivo supera el máximo de {settings.max_upload_mb} MB",
                    )
                sha256.update(chunk)
                out.write(chunk)
        if size == 0:
            raise HTTPException(status_code=400, detail="El archivo está vacío")
    except HTTPException:
        dest.unlink(missing_ok=True)
        raise

    # Encolamos el análisis: el worker lo hará en segundo plano.
    try:
        await run_in_threadpool(_enqueue, analysis_id, sha256.hexdigest(), size)
    except Exception:
        log.exception("No se pudo encolar el análisis %s", analysis_id)
        dest.unlink(missing_ok=True)
        raise HTTPException(
            status_code=503,
            detail="El servicio de análisis no está disponible, intenta de nuevo en un momento",
        )

    return AnalysisCreated(
        id=analysis_id,
        sha256=sha256.hexdigest(),
        size_bytes=size,
        status=AnalysisStatus.pending,
    )


@router.get("/{analysis_id}", response_model=AnalysisResult)
def get_analysis(analysis_id: UUID):
    data = store.load(analysis_id)
    if data is None:
        raise HTTPException(status_code=404, detail="No encontramos ese análisis")
    return data
