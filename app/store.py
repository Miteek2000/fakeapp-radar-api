"""Estado y resultado de cada análisis, guardados en PostgreSQL.

El reporte se cifra (AES-256-GCM) antes de guardarse; el hash SHA-256, el tamaño y el
nivel de riesgo se guardan sin cifrar para poder buscar y sacar estadísticas.
"""
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from app import crypto
from app.db import session_scope
from app.models import Analysis

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
        return {"id": str(row.id), "status": row.status, "report": report, "error": row.error}
