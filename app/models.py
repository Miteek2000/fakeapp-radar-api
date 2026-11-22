import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, CheckConstraint, ForeignKey, DateTime, Integer, LargeBinary, SmallInteger, String, Text, Uuid, func
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
        CheckConstraint("vt_status is null or vt_status in ('pending','found','not_found','unavailable')", name="ck_analyses_vt_status"),
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

    # VirusTotal (se consulta solo por SHA-256). Estados: pending | found | not_found | unavailable.
    vt_status: Mapped[str | None] = mapped_column(String(16))
    vt_malicious: Mapped[int | None] = mapped_column(SmallInteger)
    vt_total: Mapped[int | None] = mapped_column(SmallInteger)

    # Dueño del análisis; vacío = anónimo.
    user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id", ondelete="CASCADE"), index=True)


class PermissionCatalog(Base):
    """Permisos de Android que sabemos explicar. Solo lectura desde la API; los datos los
    carga el repo fakeapp-radar-db (seeds/)."""

    __tablename__ = "permission_catalog"
    __table_args__ = (
        CheckConstraint("severity in ('peligroso','atencion','normal')", name="ck_permission_catalog_severity"),
        CheckConstraint("weight >= 0 and weight <= 100", name="ck_permission_catalog_weight"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    android_name: Mapped[str] = mapped_column(Text, unique=True)
    friendly_title: Mapped[str] = mapped_column(Text)
    explanation: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))
    weight: Mapped[int] = mapped_column(SmallInteger)
    icon: Mapped[str] = mapped_column(String(32))
    # Nivel de protección oficial de AOSP y claves de las fuentes (ver docs/Fuentes_Catalogo_Permisos.docx en el repo -db).
    protection_level: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str | None] = mapped_column(Text)
    # true = explicación y peso escritos por el proyecto; false = texto genérico a partir de AOSP.
    curated: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")


class VtCache(Base):
    """Respuestas definitivas de VirusTotal por SHA-256, para no repetir consultas (cuota: 4/min, 500/día)."""

    __tablename__ = "vt_cache"
    __table_args__ = (
        CheckConstraint("length(sha256) = 64", name="ck_vt_cache_sha256"),
        CheckConstraint("status in ('found','not_found')", name="ck_vt_cache_status"),
    )

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String(16))
    malicious: Mapped[int | None] = mapped_column(SmallInteger)
    total: Mapped[int | None] = mapped_column(SmallInteger)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class User(Base):
    """Cuenta de usuario. Solo se guarda el hash Argon2id de la contraseña."""

    __tablename__ = "users"
    __table_args__ = (CheckConstraint("email = lower(email)", name="ck_users_email_lower"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(Text, unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class RefreshToken(Base):
    """Sesión renovable. Se guarda el SHA-256 del token, nunca el token."""

    __tablename__ = "refresh_tokens"
    __table_args__ = (CheckConstraint("length(token_hash) = 64", name="ck_refresh_tokens_hash"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="CASCADE"), index=True)
    family_id: Mapped[uuid.UUID] = mapped_column(Uuid, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rotated: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
