import uuid
from datetime import datetime

from sqlalchemy import BigInteger, CheckConstraint, DateTime, LargeBinary, SmallInteger, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class Analysis(Base):
    """Un análisis de APK. El reporte completo va cifrado; el hash y el resumen, no.

    Esta clase solo MAPEA la tabla para que la API pueda leerla y escribirla. La tabla se
    crea y se versiona en el repo fakeapp-radar-db (migraciones de Alembic).
    """

    __tablename__ = "analyses"
    __table_args__ = (
        CheckConstraint("status in ('pending','running','done','failed')", name="ck_analyses_status"),
        CheckConstraint("risk_score is null or (risk_score >= 0 and risk_score <= 100)", name="ck_analyses_score"),
        CheckConstraint("length(sha256) = 64", name="ck_analyses_sha256"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    status: Mapped[str] = mapped_column(String(16))

    # Sin cifrar a propósito: sirven para buscar y para estadísticas.
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    risk_score: Mapped[int | None] = mapped_column(SmallInteger)
    risk_level: Mapped[str | None] = mapped_column(String(8))
    error: Mapped[str | None] = mapped_column(Text)

    # Reporte completo (nombre de la app, paquete, permisos...) cifrado con AES-256-GCM.
    report_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    key_version: Mapped[int | None] = mapped_column(SmallInteger)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
