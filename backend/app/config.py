from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    GROQ_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    TELEGRAM_BOT_TOKEN: str = ""
    REDIS_URL: str = "redis://localhost:6379"
    API_BASE_URL: str = "http://localhost:8000"
    CACHE_TTL_SECONDS: int = 86400

    class Config:
        env_file = ".env"

settings = Settings()