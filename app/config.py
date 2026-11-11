from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "FakeApp Radar API"
    upload_dir: str = "uploads"
    max_upload_mb: int = 100

    # Cola de tareas y estado de los análisis (fase 4)
    redis_url: str = "redis://localhost:6379/0"
    result_ttl_seconds: int = 86400  # los resultados se guardan 24 horas
    analysis_time_limit_seconds: int = 120  # tiempo máximo por análisis


settings = Settings()
