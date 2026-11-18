from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field

from app.analysis.models import AnalysisReport


class AnalysisStatus(str, Enum):
    pending = "pending"
    running = "running"
    done = "done"
    failed = "failed"


class AnalysisCreated(BaseModel):
    id: UUID
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int
    status: AnalysisStatus


class VtStatus(str, Enum):
    pending = "pending"
    found = "found"
    not_found = "not_found"
    unavailable = "unavailable"


class VirusTotalInfo(BaseModel):
    """Reputación del archivo según VirusTotal (solo se consulta su SHA-256, el archivo no se sube)."""

    status: VtStatus
    malicious: int | None = None  # motores que lo marcan como malicioso o sospechoso
    total: int | None = None  # motores que dieron un veredicto
    url: str


class AnalysisResult(BaseModel):
    id: UUID
    status: AnalysisStatus
    report: AnalysisReport | None = None
    error: str | None = None
    virustotal: VirusTotalInfo | None = None
