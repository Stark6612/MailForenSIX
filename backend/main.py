"""
MailForenSIX — FastAPI Backend
Entry point: uvicorn main:app --reload
"""

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from api.routes import analyze, export
from core.config import settings
from core.database import init_db
from engines.classifier import load_model, model_loaded

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    # Database
    await init_db()

    # Phase 2 — Load ML classifier model (graceful if .pkl missing)
    loaded = load_model()
    if loaded:
        logger.info("[startup] ML classifier ready.")
    else:
        logger.warning(
            "[startup] ML model not found — heuristic fallback active. "
            "Run: python scripts/train_classifier.py"
        )

    yield


app = FastAPI(
    title="MailForenSIX API",
    description=(
        "AI-Powered Email Threat Detection & Forensic Intelligence Platform — "
        "SIH 2026, Problem ID #26106"
    ),
    version="0.3.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS ───────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ────────────────────────────────────────────────────────────────────
app.include_router(analyze.router, prefix="/api/v1", tags=["analysis"])
app.include_router(export.router,  prefix="/api/v1", tags=["export"])


@app.get("/health", tags=["health"])
async def health_check():
    """Liveness probe — used by Docker Compose and the frontend."""
    return {
        "status":           "ok",
        "service":          "mailforensix-backend",
        "version":          "0.3.0",
        "ml_model_loaded":  model_loaded(),
        "air_gapped":       settings.AIR_GAPPED,
    }
