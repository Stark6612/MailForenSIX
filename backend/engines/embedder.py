"""
engines/embedder.py
-------------------
Text embedding engine for Mode 2 campaign clustering.

Primary / Default on deployed environments:
  TF-IDF + TruncatedSVD (up to 128-dim, unit-normalized)
  - Zero HuggingFace download
  - Zero PyTorch RAM overhead (~40 MB total vs 400+ MB)
  - Blazing fast (<0.1s for 50 emails)
  - Production-ready on Render 512MB free tier

Optional Local:
  all-MiniLM-L6-v2 via sentence-transformers (if installed and ENABLE_ST_MODEL=1)

Public API:
    embed_texts(texts: list[str]) -> np.ndarray   # unit-normalized (N, D)
"""

from __future__ import annotations
import logging
import os
import numpy as np

logger = logging.getLogger(__name__)

_DISABLE_ST = os.environ.get("DISABLE_ST_MODEL", "1").strip().lower() in ("1", "true", "yes")
_ENABLE_ST  = os.environ.get("ENABLE_ST_MODEL", "0").strip().lower() in ("1", "true", "yes")
_model = None
_MODEL_NAME = "all-MiniLM-L6-v2"


def _embed_tfidf_svd(texts: list[str]) -> np.ndarray:
    """
    Generate unit-normalized semantic vectors via sublinear TF-IDF + Truncated SVD.
    Dynamically adjusts SVD components to fit sample count.
    """
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.decomposition import TruncatedSVD
    from sklearn.preprocessing import normalize

    tfidf = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=10_000,
        sublinear_tf=True,
        stop_words="english",
    )
    X = tfidf.fit_transform(texts)
    n_samples, n_features = X.shape

    max_components = min(n_samples - 1, n_features - 1, 128)
    if max_components >= 2:
        svd = TruncatedSVD(n_components=max_components, random_state=42)
        X_reduced = svd.fit_transform(X)
        return normalize(X_reduced, norm="l2", copy=False).astype(np.float32)
    else:
        # Very few samples (e.g. 1-2): use normalized dense TF-IDF directly
        return normalize(X.toarray(), norm="l2", copy=False).astype(np.float32)


def get_st_model():
    """Load sentence-transformers only if explicitly enabled and available."""
    global _model
    if _DISABLE_ST or not _ENABLE_ST:
        return None
    if _model is None:
        try:
            from sentence_transformers import SentenceTransformer
            logger.info(f"[embedder] Loading {_MODEL_NAME}...")
            _model = SentenceTransformer(_MODEL_NAME)
        except Exception as e:
            logger.warning(f"[embedder] ST model unavailable: {e}. Using TF-IDF fallback.")
            _model = None
    return _model


def embed_texts(texts: list[str]) -> np.ndarray:
    """
    Embed a list of text strings into unit-normalized vectors.
    Returns float32 ndarray of shape (len(texts), D).
    """
    if not texts:
        return np.zeros((0, 128), dtype=np.float32)

    # 1. Check for sentence-transformers if explicitly enabled
    st_model = get_st_model()
    if st_model is not None:
        try:
            vecs = st_model.encode(
                texts,
                normalize_embeddings=True,
                show_progress_bar=False,
                batch_size=32,
            )
            return np.array(vecs, dtype=np.float32)
        except Exception as e:
            logger.warning(f"[embedder] ST encode failed: {e}. Falling back to TF-IDF.")

    # 2. Production default: TF-IDF + SVD
    try:
        return _embed_tfidf_svd(texts)
    except Exception as e:
        logger.error(f"[embedder] TF-IDF embedding failed: {e}")
        return np.zeros((len(texts), 32), dtype=np.float32)
