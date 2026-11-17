"""Política de retención: qué se conserva y por cuánto tiempo.

- Análisis (fila + reporte cifrado): `retention_days` días desde que se crearon.
- Archivos APK sueltos en la carpeta de subidas (el worker normalmente los borra al terminar,
  pero si algo se cae pueden quedar): `orphan_upload_hours` horas.

Correr a mano:  python -m app.worker.maintenance [--days N] [--hours N]
"""
import argparse
import logging
import time
from pathlib import Path

from app import store
from app.config import settings
from app.worker.celery_app import celery_app

log = logging.getLogger(__name__)


def purge_orphan_uploads(upload_dir: str | Path, hours: int) -> int:
    """Borra los .apk más viejos que `hours` horas. No toca otros archivos ni subcarpetas."""
    folder = Path(upload_dir)
    if not folder.is_dir():
        return 0
    limit = time.time() - hours * 3600
    removed = 0
    for f in folder.glob("*.apk"):
        if f.is_file() and not f.is_symlink() and f.stat().st_mtime < limit:
            f.unlink(missing_ok=True)
            removed += 1
    return removed


def run(days: int | None = None, hours: int | None = None) -> dict[str, int]:
    days = settings.retention_days if days is None else days
    hours = settings.orphan_upload_hours if hours is None else hours
    result = {
        "analyses_deleted": store.purge_older_than(days),
        "uploads_deleted": purge_orphan_uploads(settings.upload_dir, hours),
    }
    log.info("Limpieza de retención: %s", result)
    return result


@celery_app.task(name="purge_expired")
def purge_expired_task() -> dict[str, int]:
    return run()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Limpieza de retención")
    ap.add_argument("--days", type=int, help="días de retención de análisis (por defecto: RETENTION_DAYS)")
    ap.add_argument("--hours", type=int, help="horas para borrar APK sueltos (por defecto: ORPHAN_UPLOAD_HOURS)")
    args = ap.parse_args()
    print(run(args.days, args.hours))
