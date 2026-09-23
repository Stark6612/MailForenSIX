"""
engines/embedder.py
-------------------
Sentence embedding engine using all-MiniLM-L6-v2 (DistilBERT-based).
Produces unit-normalized 384-dim vectors for Mode 2 campaign clustering.

Public API:
    embed_texts(texts: list[str]) -> np.ndarray   # shape (N, 384), unit-normalized
    get_model()                                    # lazy-load singleton
"""

from __future__ import annotations
import logging
import numpy as np
from pathlib import Path

logger = logging.getLogger(__name__)
_model = None
_MODEL_NAME = "all-MiniLM-L6-v2"


def get_model():
    global _model
    if _model is None:
        try:
            from sentence_transformers import SentenceTransformer
            logger.info(f"[embedder] Loading {_MODEL_NAME}...")
            _model = SentenceTransformer(_MODEL_NAME)
            logger.info("[embedder] Model loaded.")
        except Exception as e:
            logger.error(f"[embedder] Failed to load model: {e}")
            _model = None
    return _model


def embed_texts(texts: list[str]) -> np.ndarray:
    """
    Embed a list of texts. Returns unit-normalized (N, 384) float32 array.
    Falls back to random unit vectors if model unavailable.
    """
    if not texts:
        return np.zeros((0, 384), dtype=np.float32)

    model = get_model()
    if model is None:
        logger.warning("[embedder] Model not loaded - using zero embeddings (fallback)")
        # Return zero vectors - clustering will rely entirely on Jaccard distance
        vecs = np.zeros((len(texts), 384), dtype=np.float32)
        return vecs

    try:
        vecs = model.encode(
            texts,
            normalize_embeddings=True,
            show_progress_bar=False,
            batch_size=32,
        )
        return np.array(vecs, dtype=np.float32)
    except Exception as e:
        logger.error(f"[embedder] Encoding error: {e}")
        return np.zeros((len(texts), 384), dtype=np.float32)
