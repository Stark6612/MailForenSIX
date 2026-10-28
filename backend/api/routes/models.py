"""
api/routes/models.py — Phase 6.2 (AICS Benchmark & Multi-Model Registry REST API)
Course: Artificial Intelligence for Cyber Security (23AI2001)

Endpoints:
  GET /api/v1/models                    → Active models in dynamic registry
  GET /api/v1/models/benchmark          → Empirical multi-model comparative performance matrix
  GET /api/v1/models/benchmark/ablation → Feature representation ablation experiment results
  GET /api/v1/models/benchmark/av-limits → Antivirus signature evasion vs AI benchmark
  GET /api/v1/models/plots/{plot_name}  → Publication-grade diagnostic charts
"""

import json
from pathlib import Path
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, JSONResponse

import time
from pydantic import BaseModel
from engines.classifier import get_available_models, MODEL_METADATA, predict_intent, load_model

router = APIRouter()

PROOF_AICS = Path(__file__).resolve().parent.parent.parent / "proof" / "aics"


class SandboxRequest(BaseModel):
    text: str


@router.post("/sandbox", summary="Evaluate all 5 AICS models in parallel on arbitrary text")
async def evaluate_sandbox(payload: SandboxRequest):
    """
    Evaluates all 5 AICS models (LR, SVM, NB, DT, HistGB) directly in-memory
    on arbitrary email text or bodies, returning predictions, confidences,
    class probabilities, and per-model inference latencies.
    """
    text = (payload.text or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="Text cannot be empty.")

    load_model()
    results = []

    for mid, meta in MODEL_METADATA.items():
        t0 = time.perf_counter()
        try:
            label, conf, probs, name = predict_intent(text, mid)
            lat_ms = round((time.perf_counter() - t0) * 1000, 2)

            p_phish = probs.get("phishing", 0.0)
            p_spam  = probs.get("spam", 0.0)
            score = int(round(p_phish * 100 + p_spam * 40))
            score = max(0, min(100, score))
            tier = "critical" if score >= 85 else ("high" if score >= 60 else ("suspicious" if score >= 30 else "safe"))

            results.append({
                "key": mid,
                "name": meta["name"],
                "type": meta["type"],
                "label": label,
                "confidence": round(conf, 4),
                "probs": {k: round(v, 4) for k, v in probs.items()},
                "latency_ms": lat_ms,
                "riskScore": score,
                "riskTier": tier
            })
        except Exception as exc:
            results.append({
                "key": mid,
                "name": meta["name"],
                "type": meta["type"],
                "label": "unknown",
                "confidence": 0.0,
                "probs": {},
                "latency_ms": 0.0,
                "riskScore": 0,
                "riskTier": "safe",
                "error": str(exc)
            })

    return {
        "status": "success",
        "sample_preview": text[:120],
        "models_evaluated": len(results),
        "results": results
    }


@router.get("", summary="List active machine learning models in registry")
async def list_models():
    """Returns all models trained for Course 23AI2001 available for runtime inference."""
    return {
        "status": "success",
        "total_models": len(MODEL_METADATA),
        "default_model": "lr",
        "models": get_available_models()
    }


@router.get("/benchmark", summary="Get multi-model comparative benchmark metrics")
async def get_model_benchmark():
    """Returns empirical evaluation matrix: Accuracy, Precision, Recall, F1, Latency, and Size."""
    bench_file = PROOF_AICS / "aics_model_benchmark.json"
    if not bench_file.exists():
        raise HTTPException(status_code=404, detail="Benchmark metrics file not found.")
    
    with open(bench_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    return JSONResponse(content=data)


@router.get("/benchmark/ablation", summary="Get feature representation ablation study")
async def get_ablation_results():
    """Returns ablation study results comparing BoW, Unigram TF-IDF, Bigram TF-IDF, and Hybrid features."""
    ablation_file = PROOF_AICS / "aics_ablation_results.json"
    if not ablation_file.exists():
        raise HTTPException(status_code=404, detail="Ablation results file not found.")

    with open(ablation_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    return JSONResponse(content=data)


@router.get("/benchmark/av-limits", summary="Get Antivirus vs AI threat limits comparison (CO2)")
async def get_av_limits():
    """Returns CO2 benchmark data evaluating cryptographic hash AV vs semantic NLP on polymorphic zero-days."""
    av_file = PROOF_AICS / "av_vs_ai_limits.json"
    if not av_file.exists():
        raise HTTPException(status_code=404, detail="Antivirus limits benchmark file not found.")

    with open(av_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    return JSONResponse(content=data)


@router.get("/plots/{plot_name}", summary="Serve benchmark diagnostic plot images")
async def get_benchmark_plot(plot_name: str):
    """
    Serves generated publication figures:
      - confusion_matrices
      - roc_curves
      - latency_pareto
      - pr_curves
      - feature_ablation
      - lime_attribution
      - av_limits
    """
    allowed_plots = {
        "confusion_matrices": "aics_confusion_matrices.png",
        "roc_curves":         "aics_roc_curves.png",
        "latency_pareto":     "aics_latency_pareto.png",
        "pr_curves":          "aics_pr_curves.png",
        "feature_ablation":   "aics_feature_ablation.png",
        "lime_attribution":   "aics_lime_attribution.png",
        "av_limits":          "aics_av_limits_comparison.png",
    }

    filename = allowed_plots.get(plot_name.lower())
    if not filename:
        raise HTTPException(
            status_code=404,
            detail=f"Plot '{plot_name}' not found. Available: {list(allowed_plots.keys())}"
        )

    file_path = PROOF_AICS / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"Image file {filename} does not exist.")

    return FileResponse(file_path, media_type="image/png")

