from pydantic_settings import BaseSettings
from pathlib import Path

ENV_FILE = Path(__file__).resolve().parent.parent.parent / ".env"

class Settings(BaseSettings):
    GROQ_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    REDIS_URL: str = "redis://localhost:6379"
    SANDBOX_URL: str = ""
    CACHE_TTL_SECONDS: int = 3600

    model_config = {
        "env_file": str(ENV_FILE),
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }

settings = Settings()
