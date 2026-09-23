"""
engines/embedder.py
-------------------
Sentence embedding engine for Mode 2 campaign clustering.

Primary:  all-MiniLM-L6-v2 via sentence-transformers (if already cached locally)
Fallback: TF-IDF + TruncatedSVD (128-dim) — used when model not cached or
          DISABLE_ST_MODEL=1 env var is set (e.g. Render free tier).

Public API:
    embed_texts(texts: list[str]) -> np.ndarray   # unit-normalized
    get_model()                                    # lazy-load singleton
"""

from __future__ import annotations
import logging
import os
import numpy as np
from pathlib import Path

logger = logging.getLogger(__name__)
_model = None
_tfidf_pipeline = None
_MODEL_NAME = "all-MiniLM-L6-v2"

# Set DISABLE_ST_MODEL=1 on Render to skip HuggingFace download entirely
_DISABLE_ST = os.environ.get("DISABLE_ST_MODEL", "").strip() in ("1", "true", "True")


def _load_tfidf_pipeline():
    """TF-IDF + SVD lightweight fallback embedder (no download needed)."""
    global _tfidf_pipeline
    if _tfidf_pipeline is not None:
        return _tfidf_pipeline
    from sklearn.pipeline import Pipeline
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.decomposition import TruncatedSVD
    from sklearn.preprocessing import Normalizer
    _tfidf_pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=20_000, sublinear_tf=True)),
        ("svd",   TruncatedSVD(n_components=128, random_state=42)),
        ("norm",  Normalizer(copy=False)),
    ])
    logger.info("[embedder] TF-IDF+SVD fallback pipeline ready (128-dim).")
    return _tfidf_pipeline


def get_model():
    global _model
    if _DISABLE_ST:
        logger.info("[embedder] ST disabled via DISABLE_ST_MODEL — using TF-IDF fallback.")
        return None
    if _model is None:
        try:
            from sentence_transformers import SentenceTransformer
            # Only load if already cached — do NOT trigger a download at request time
            hf_cache = Path.home() / ".cache" / "huggingface" / "hub"
            st_cache = Path.home() / ".cache" / "torch" / "sentence_transformers"
            cached = (
                (hf_cache.exists() and any(hf_cache.rglob("*.safetensors"))) or
                (st_cache.exists() and any(st_cache.rglob("*.bin")))
            )
            if cached:
                logger.info(f"[embedder] Loading {_MODEL_NAME} from local cache...")
                _model = SentenceTransformer(_MODEL_NAME)
                logger.info("[embedder] Sentence-transformer model loaded.")
            else:
                logger.warning("[embedder] Model not cached — using TF-IDF fallback (no download).")
        except Exception as e:
            logger.error(f"[embedder] ST load failed: {e} — using TF-IDF fallback.")
    return _model


def embed_texts(texts: list[str]) -> np.ndarray:
    """
    Embed texts. Returns unit-normalized float32 array.
    Uses sentence-transformers if cached, TF-IDF+SVD otherwise.
    """
    if not texts:
        return np.zeros((0, 128), dtype=np.float32)

    model = get_model()
    if model is not None:
        try:
            vecs = model.encode(texts, normalize_embeddings=True,
                                show_progress_bar=False, batch_size=32)
            return np.array(vecs, dtype=np.float32)
        except Exception as e:
            logger.error(f"[embedder] Encoding error: {e} — falling back to TF-IDF")

    # Fallback: TF-IDF + SVD (all deps already installed, no network needed)
    logger.info("[embedder] Using TF-IDF+SVD fallback embeddings.")
    pipeline = _load_tfidf_pipeline()
    try:
        vecs = pipeline.fit_transform(texts)
        return np.array(vecs, dtype=np.float32)
    except Exception as e:
        logger.error(f"[embedder] TF-IDF fallback error: {e}")
        return np.zeros((len(texts), 128), dtype=np.float32)
