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


class AnalysisResult(BaseModel):
    id: UUID
    status: AnalysisStatus
    report: AnalysisReport | None = None
    error: str | None = None
