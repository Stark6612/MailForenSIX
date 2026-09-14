"""
Core configuration — reads from .env with safe defaults for local dev.
"""

from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    # App
    APP_NAME: str = "MailForenSIX"
    DEBUG: bool = True

    # CORS — frontend dev server + production
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",   # Vite dev server
        "http://localhost:3000",
        "http://127.0.0.1:5173",
    ]

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./mailforensix.db"

    # Geolocation (ip-api.com free tier — no key needed)
    GEO_API_BASE: str = "http://ip-api.com/json"
    GEO_API_BATCH: str = "http://ip-api.com/batch"

    # Air-gap toggle — when True, disables ALL live external API calls
    # and falls back to local SQLite cache + MaxMind GeoLite2
    AIR_GAPPED: bool = False

    # MaxMind GeoLite2 offline DB path (populated in Phase 2)
    MAXMIND_DB_PATH: str = "./data/GeoLite2-City.mmdb"

    # Risk score weights (must sum to 1.0)
    WEIGHT_AUTH: float = 0.30
    WEIGHT_INTENT: float = 0.30
    WEIGHT_GEO: float = 0.20
    WEIGHT_DOMAIN: float = 0.20

    # ML model path (populated after training in Phase 2)
    MODEL_PATH: str = "./models/mailforensix_model.pkl"
    VECTORIZER_PATH: str = "./models/tfidf_vectorizer.pkl"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
