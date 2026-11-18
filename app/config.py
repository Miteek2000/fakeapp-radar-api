from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "FakeApp Radar API"
    upload_dir: str = "uploads"
    max_upload_mb: int = 100

    # Cola de tareas (fase 4): Redis solo se usa como bandeja de mensajes.
    redis_url: str = "redis://localhost:6379/0"
    analysis_time_limit_seconds: int = 120  # tiempo máximo por análisis

    # Base de datos (repo fakeapp-radar-db). Ejemplo:
    # postgresql+psycopg://fakeapp:CLAVE@fakeapp-db:5432/fakeapp_radar
    database_url: str = ""

    # Retención: los análisis se borran pasados estos días; los APK que quedaron sueltos, pasadas estas horas.
    retention_days: int = 30
    orphan_upload_hours: int = 24

    # VirusTotal (fase 7). La clave la usa SOLO el servicio vt-worker.
    vt_api_key: str = ""
    vt_cache_hours: int = 24
    vt_pending_max_minutes: int = 15  # pasado este tiempo, un 'pending' se muestra como no disponible

    # Clave AES-256 (32 bytes en base64) para cifrar los reportes. Nunca va en el código.
    encryption_key: str = ""


settings = Settings()
