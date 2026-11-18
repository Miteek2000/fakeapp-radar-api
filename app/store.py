"""Estado y resultado de cada análisis, guardados en PostgreSQL.

El reporte se cifra (AES-256-GCM) antes de guardarse; el hash SHA-256, el tamaño y el
nivel de riesgo se guardan sin cifrar para poder buscar y sacar estadísticas.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import delete

from app import crypto
from app.db import session_scope
from app.config import settings
from app.models import Analysis, VtCache

log = logging.getLogger(__name__)


def _aad(analysis_id: UUID) -> str:
    return f"analysis:{analysis_id}"


def create(analysis_id: str | UUID, sha256: str, size_bytes: int) -> None:
    """Registra un análisis nuevo en estado 'pending'."""
    with session_scope() as session:
        session.add(Analysis(id=UUID(str(analysis_id)), status="pending", sha256=sha256, size_bytes=size_bytes))


def discard(analysis_id: str | UUID) -> None:
    """Borra el registro (se usa si no se pudo encolar el análisis)."""
    with session_scope() as session:
        row = session.get(Analysis, UUID(str(analysis_id)))
        if row is not None:
            session.delete(row)


def save(analysis_id: str | UUID, status, report: dict | None = None, error: str | None = None) -> None:
    """Actualiza el estado; si hay reporte, lo guarda cifrado."""
    uid = UUID(str(analysis_id))
    value = getattr(status, "value", status)
    with session_scope() as session:
        row = session.get(Analysis, uid)
        if row is None:
            log.warning("Se intentó actualizar un análisis que no existe: %s", uid)
            return
        row.status = value
        if value in ("done", "failed"):
            row.finished_at = datetime.now(timezone.utc)
        if report is not None:
            row.report_enc = crypto.encrypt_json(report, _aad(uid))
            row.key_version = crypto.KEY_VERSION
            row.risk_score = report["risk_score"]
            row.risk_level = getattr(report["risk_level"], "value", report["risk_level"])
        if error is not None:
            row.error = error


def load(analysis_id: str | UUID) -> dict[str, Any] | None:
    uid = UUID(str(analysis_id))
    with session_scope() as session:
        row = session.get(Analysis, uid)
        if row is None:
            return None
        report = crypto.decrypt_json(row.report_enc, _aad(uid)) if row.report_enc else None
        return {
            "id": str(row.id),
            "status": row.status,
            "report": report,
            "error": row.error,
            "virustotal": _vt_view(row),
        }


def purge_older_than(days: int) -> int:
    """Borra los análisis creados hace más de `days` días. Devuelve cuántos borró."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    with session_scope() as session:
        result = session.execute(delete(Analysis).where(Analysis.created_at < cutoff))
        return result.rowcount or 0


# ---------- VirusTotal ----------

def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _vt_view(row: Analysis) -> dict | None:
    if row.vt_status is None:
        return None
    status = row.vt_status
    if status == "pending" and row.updated_at is not None:
        limit = timedelta(minutes=settings.vt_pending_max_minutes)
        if datetime.now(timezone.utc) - _aware(row.updated_at) > limit:
            status = "unavailable"  # nadie contestó a tiempo (servicio apagado o cola atorada)
    return {
        "status": status,
        "malicious": row.vt_malicious,
        "total": row.vt_total,
        "url": f"https://www.virustotal.com/gui/file/{row.sha256}",
    }


def set_vt_pending(analysis_id: str | UUID) -> None:
    with session_scope() as session:
        row = session.get(Analysis, UUID(str(analysis_id)))
        if row is not None:
            row.vt_status = "pending"


def save_vt(analysis_id: str | UUID, status: str, malicious: int | None = None, total: int | None = None) -> None:
    with session_scope() as session:
        row = session.get(Analysis, UUID(str(analysis_id)))
        if row is None:
            log.warning("Resultado de VirusTotal para un análisis que ya no existe: %s", analysis_id)
            return
        row.vt_status, row.vt_malicious, row.vt_total = status, malicious, total


def vt_cache_get(sha256: str) -> dict | None:
    """Respuesta guardada hace menos de `vt_cache_hours` horas, o None."""
    limit = datetime.now(timezone.utc) - timedelta(hours=settings.vt_cache_hours)
    with session_scope() as session:
        row = session.get(VtCache, sha256)
        if row is None or _aware(row.checked_at) < limit:
            return None
        return {"status": row.status, "malicious": row.malicious, "total": row.total}


def vt_cache_put(sha256: str, status: str, malicious: int | None, total: int | None) -> None:
    with session_scope() as session:
        row = session.get(VtCache, sha256)
        now = datetime.now(timezone.utc)
        if row is None:
            session.add(VtCache(sha256=sha256, status=status, malicious=malicious, total=total, checked_at=now))
        else:
            row.status, row.malicious, row.total, row.checked_at = status, malicious, total, now
