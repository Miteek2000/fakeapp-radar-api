import hashlib
import zipfile
from pathlib import Path

from androguard.core.apk import APK
from loguru import logger

from app.analysis.catalog import lookup
from app.analysis.models import (
    AnalysisReport,
    Hashes,
    PermissionCounts,
    PermissionFinding,
)

logger.disable("androguard")

CHUNK_SIZE = 1024 * 1024
SEVERITY_ORDER = {"peligroso": 0, "atencion": 1, "normal": 2}

MAX_UNCOMPRESSED_MB = 500
MAX_ENTRIES = 20000
MAX_RATIO = 100


class InvalidApkError(Exception):
    """El archivo no es un APK que podamos analizar con seguridad."""


def check_zip_safety(
    path: Path,
    max_uncompressed_mb: int = MAX_UNCOMPRESSED_MB,
    max_entries: int = MAX_ENTRIES,
    max_ratio: int = MAX_RATIO,
) -> None:
    try:
        with zipfile.ZipFile(path) as z:
            infos = z.infolist()
            names = {i.filename for i in infos}
    except zipfile.BadZipFile as exc:
        raise InvalidApkError("El archivo no es un ZIP/APK válido") from exc

    if "AndroidManifest.xml" not in names:
        raise InvalidApkError("El APK no tiene AndroidManifest.xml")
    if len(infos) > max_entries:
        raise InvalidApkError("El APK tiene demasiados archivos internos")

    uncompressed = sum(i.file_size for i in infos)
    compressed = max(sum(i.compress_size for i in infos), 1)
    if uncompressed > max_uncompressed_mb * 1024 * 1024:
        raise InvalidApkError("El APK ocupa demasiado al descomprimirse")
    if uncompressed / compressed > max_ratio:
        raise InvalidApkError("El APK tiene una compresión sospechosa")


def compute_hashes(path: Path) -> Hashes:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return Hashes(md5=md5.hexdigest(), sha1=sha1.hexdigest(), sha256=sha256.hexdigest())


def _to_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def build_finding(android_name: str) -> PermissionFinding:
    entry = lookup(android_name)
    if entry is None:
        return PermissionFinding(
            android_name=android_name,
            title=android_name.rsplit(".", 1)[-1],
            explanation="Este permiso todavía no está en nuestro catálogo.",
            severity="normal",
            weight=0,
            icon="help-circle",
            known=False,
        )
    return PermissionFinding(
        android_name=android_name,
        title=entry.friendly_title,
        explanation=entry.explanation,
        severity=entry.severity,
        weight=entry.weight,
        icon=entry.icon,
        known=True,
    )


def calculate_risk(findings: list[PermissionFinding]) -> tuple[int, str]:
    """Puntaje = suma de pesos de los permisos, con tope de 100.
    Niveles: bajo 0-29, medio 30-59, alto 60-100 (ajustables)."""
    score = min(100, sum(f.weight for f in findings))
    if score >= 60:
        return score, "alto"
    if score >= 30:
        return score, "medio"
    return score, "bajo"


def analyze_apk(path: str | Path, **zip_limits) -> AnalysisReport:
    path = Path(path)
    check_zip_safety(path, **zip_limits)

    try:
        apk = APK(str(path))
        if not apk.is_valid_APK():
            raise ValueError("AndroidManifest.xml ilegible")
        permissions = set(apk.get_permissions())
        package_name = apk.get_package()
        min_sdk = _to_int(apk.get_min_sdk_version())
        target_sdk = _to_int(apk.get_target_sdk_version())
        try:
            version_name = apk.get_androidversion_name()
        except Exception:
            version_name = None
        try:
            app_name = apk.get_app_name()
        except Exception:
            app_name = None
    except Exception as exc:
        raise InvalidApkError("No se pudo leer el contenido del APK") from exc

    findings = [build_finding(name) for name in permissions]
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], -f.weight, f.android_name))

    counts = PermissionCounts()
    for f in findings:
        setattr(counts, f.severity, getattr(counts, f.severity) + 1)

    score, level = calculate_risk(findings)

    return AnalysisReport(
        package_name=package_name,
        app_name=app_name,
        version_name=version_name,
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        size_bytes=path.stat().st_size,
        hashes=compute_hashes(path),
        permissions=findings,
        counts=counts,
        risk_score=score,
        risk_level=level,
    )
