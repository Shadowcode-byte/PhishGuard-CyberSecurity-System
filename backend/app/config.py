from pydantic_settings import BaseSettings
from pydantic import ConfigDict
from typing import Optional
import secrets


class Settings(BaseSettings):
    # App
    APP_NAME: str = "PhishGuard"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    SECRET_KEY: str = secrets.token_urlsafe(32)

    # Database (FIXED for local)
    DATABASE_URL: str = "postgresql://postgres:postgres@localhost:5432/phishguard"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # ✅ Upstash (optional)
    UPSTASH_REDIS_REST_URL: Optional[str] = None
    UPSTASH_REDIS_REST_TOKEN: Optional[str] = None

    # JWT
    JWT_SECRET_KEY: str = secrets.token_urlsafe(32)
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # APIs
    ENCRYPTION_KEY: Optional[str] = None
    OPENROUTER_API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None
    GEMINI_API_KEY: Optional[str] = None
    GROQ_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None

    # File uploads
    MAX_FILE_SIZE_MB: int = 10
    UPLOAD_DIR: str = "./uploads"

    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = 30

    # Admin
    ADMIN_EMAIL: str = "admin@phishguard.io"

    # CORS
    ALLOWED_ORIGINS: list = [
        "http://localhost:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
    ]

    # ✅ Pydantic v2 config
    model_config = ConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore"
    )


settings = Settings()