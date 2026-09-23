"""
MailForenSIX — FastAPI Backend
Entry point: uvicorn main:app --reload
"""

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse
from contextlib import asynccontextmanager

from api.routes import analyze, export
from api.routes import campaign as campaign_route
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

    # Mode 2 — DistilBERT embedding model is loaded LAZILY on first campaign request.
    # Do NOT preload here: sentence-transformers + PyTorch consume ~400 MB which
    # exceeds Render's 512 MB free-tier limit and causes OOM at startup.
    logger.info("[startup] Mode 2 embedder will lazy-load on first /campaign/analyze request.")

    yield



app = FastAPI(
    title="MailForensix API",
    description=(
        "AI-Powered Email Campaign Intelligence Platform — "
        "SIH 2026, Problem ID #26106 | Mode 1: Single-Email Triage | Mode 2: Campaign Clustering"
    ),
    version="0.4.0",
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
app.include_router(analyze.router,          prefix="/api/v1", tags=["analysis"])
app.include_router(export.router,           prefix="/api/v1", tags=["export"])
app.include_router(campaign_route.router,   prefix="/api/v1", tags=["campaign"])


@app.api_route("/", methods=["GET", "HEAD", "POST"], include_in_schema=False)
async def root():
    """Root route — redirect browser visits to Swagger interactive API docs."""
    return RedirectResponse(url="/docs", status_code=307)


@app.get("/health", tags=["health"])
async def health_check():
    """Liveness probe — used by Docker Compose and the frontend."""
    return {
        "status":           "ok",
        "service":          "mailforensix-backend",
        "version":          "0.4.0",
        "ml_model_loaded":  model_loaded(),
        "air_gapped":       settings.AIR_GAPPED,
        "mode2_available":  True,
    }
