from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["peligroso", "atencion", "normal"]
RiskLevel = Literal["bajo", "medio", "alto"]


class Hashes(BaseModel):
    md5: str
    sha1: str
    sha256: str


class PermissionFinding(BaseModel):
    android_name: str
    title: str
    explanation: str
    severity: Severity
    weight: int
    icon: str
    known: bool


class PermissionCounts(BaseModel):
    peligroso: int = 0
    atencion: int = 0
    normal: int = 0


class AnalysisReport(BaseModel):
    package_name: str | None = None
    app_name: str | None = None
    version_name: str | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    size_bytes: int
    hashes: Hashes
    permissions: list[PermissionFinding]
    counts: PermissionCounts
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
