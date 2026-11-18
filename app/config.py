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

    # Usuarios y sesiones (fase 8).
    # Clave privada RSA para firmar los tokens de acceso (RS256): PEM codificado en base64. Solo la usa la API.
    jwt_private_key_b64: str = ""
    jwt_issuer: str = "fakeapp-radar-api"
    jwt_audience: str = "fakeapp-radar-web"
    access_token_minutes: int = 15
    refresh_token_days: int = 7
    refresh_reuse_grace_seconds: int = 10  # tolerancia a dos pestañas que refrescan a la vez
    refresh_cookie_path: str = "/"
    cookie_secure: bool = False  # True cuando se sirva por HTTPS (fase 12)
    # Orígenes del navegador que pueden usar las rutas con cookie (protección contra CSRF), separados por coma.
    allowed_origins: str = "http://localhost:3000,http://127.0.0.1:3000,http://localhost:8000,http://127.0.0.1:8000"
    # True = se puede analizar sin cuenta (el análisis queda sin dueño). False = hace falta iniciar sesión.
    allow_anonymous: bool = True

    # Límite de peticiones por IP (slowapi).
    rate_limit_enabled: bool = True
    rate_limit_storage_uri: str = "memory://"  # en Docker: la base 1 de Redis
    rate_upload: str = "5/minute"
    rate_login: str = "5/minute"
    rate_register: str = "5/minute"
    rate_refresh: str = "30/minute"
    rate_default: str = "120/minute"
    trust_proxy_headers: bool = False  # True solo detrás de un proxy propio (X-Forwarded-For)

    # Clave AES-256 (32 bytes en base64) para cifrar los reportes. Nunca va en el código.
    encryption_key: str = ""


settings = Settings()


def allowed_origins_list() -> list[str]:
    return [o.strip() for o in settings.allowed_origins.split(",") if o.strip()]
