import os
from pathlib import Path
from dotenv import load_dotenv

# Force load .env from the backend/ folder
backend_dir = Path(_file_).parent.parent
env_path = backend_dir / ".env"
load_dotenv(dotenv_path=env_path, override=True)

print(f"[CONFIG] Loading .env from: {env_path}")
print(f"[CONFIG] .env exists: {env_path.exists()}")
print(f"[CONFIG] GROQ KEY loaded: {os.getenv('GROQ_API_KEY', 'EMPTY')[:15]}")

class Settings:
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")
    API_BASE_URL: str = os.getenv("API_BASE_URL", "http://localhost:8000")
    CACHE_TTL_SECONDS: int = 86400

settings = Settings()