import hashlib
import logging
import uuid
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, Response, UploadFile, status
from starlette.concurrency import run_in_threadpool

from app import store
from app.auth.deps import UNAUTHORIZED, current_user, optional_user
from app.auth.service import UserView
from app.config import settings
from app.ratelimit import limiter
from app.schemas import AnalysisCreated, AnalysisList, AnalysisResult, AnalysisStatus
from app.worker.tasks import analyze_apk_task

log = logging.getLogger(__name__)
router = APIRouter(prefix="/analyses", tags=["analyses"])

CHUNK_SIZE = 1024 * 1024  # 1 MB
ZIP_MAGIC = b"PK\x03\x04"  # un APK es un archivo ZIP


def _enqueue(analysis_id: UUID, sha256: str, size: int, user_id: UUID | None) -> None:
    # Primero el registro (el worker lo va a actualizar) y luego la tarea.
    store.create(analysis_id, sha256, size, user_id)
    try:
        analyze_apk_task.delay(str(analysis_id))
    except Exception:
        store.discard(analysis_id)  # no dejamos un análisis "pending" que nadie va a procesar
        raise


@router.post("", response_model=AnalysisCreated, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit(lambda: settings.rate_upload)
async def create_analysis(
    request: Request,
    response: Response,
    file: UploadFile = File(...),
    user: UserView | None = Depends(optional_user),
):
    if user is None and not settings.allow_anonymous:
        raise HTTPException(status_code=401, detail="Inicia sesión para analizar un archivo.", headers=UNAUTHORIZED)
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
        await run_in_threadpool(_enqueue, analysis_id, sha256.hexdigest(), size, user.id if user else None)
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


@router.get("", response_model=AnalysisList)
def list_my_analyses(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    user: UserView = Depends(current_user),
):
    """Historial de los análisis hechos con tu cuenta."""
    return {"items": store.list_for_user(user.id, limit, offset), "limit": limit, "offset": offset}


@router.get("/{analysis_id}", response_model=AnalysisResult)
def get_analysis(analysis_id: UUID, user: UserView | None = Depends(optional_user)):
    data = store.load(analysis_id)
    # Un análisis con dueño solo lo ve su dueño. Para los demás "no existe" (así ni se sabe que existe).
    if data is None or (data["user_id"] is not None and (user is None or data["user_id"] != str(user.id))):
        raise HTTPException(status_code=404, detail="No encontramos ese análisis")
    return data
