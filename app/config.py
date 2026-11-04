from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "FakeApp Radar API"
    upload_dir: str = "uploads"
    max_upload_mb: int = 100


settings = Settings()