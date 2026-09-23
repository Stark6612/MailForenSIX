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

    # Mode 2 — Preload DistilBERT embedding model (non-blocking)
    try:
        from engines.embedder import get_model
        get_model()
        logger.info("[startup] DistilBERT embedder ready.")
    except Exception as e:
        logger.warning(f"[startup] DistilBERT embedder not loaded: {e}")

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


@app.get("/", include_in_schema=False)
async def root():
    """Root route — returns project identity card (JSON). Browser visits redirect to /docs."""
    return JSONResponse({
        "project":      "MailForenSIX",
        "description":  "AI-Powered Email Forensic & Campaign Intelligence Platform",
        "problem_id":   "#26106",
        "hackathon":    "Smart India Hackathon 2026",
        "version":      "0.4.0",
        "mode1":        "Single-Email Triage  →  POST /api/v1/analyze",
        "mode2":        "Campaign Intelligence →  POST /api/v1/campaign/analyze",
        "docs":         "http://localhost:8000/docs",
        "health":       "http://localhost:8000/health",
        "frontend":     "http://localhost:5173",
        "datasets":     "103,360 emails (10 sources, Apache 2.0)",
        "classifier":   "TF-IDF(1-3gram, 50k) + XGBoost(n=200, d=6)  |  F1=0.9631  Acc=96.16%",
        "mode2_engine": "all-MiniLM-L6-v2 embeddings + UMAP + HDBSCAN  |  ARI=0.8806",
        "air_gapped":   str(settings.AIR_GAPPED),
        "threat_intel": "URLhaus 5,728 domains + SPF/DMARC cache (52 institutional domains)",
        "exports":      "STIX 2.1  |  Sigma  |  Suricata  |  Postfix  |  Exchange  |  DNSBL",
        "github":       "https://github.com/Stark6612/MailForenSIX",
    })


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
