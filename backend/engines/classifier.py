"""
engines/classifier.py — Phase 2
TF-IDF + XGBoost intent classifier with LIME sentence explanations.

Public API:
    load_model()                       → loads .pkl files at startup (cached)
    predict_intent(text)               → (ThreatLabel, confidence: float)
    explain_sentences(body, n=8)       → list[LIMESentence]
    model_loaded()                     → bool

Models stored in:
    backend/models/mailforensix_model.pkl
    backend/models/tfidf_vectorizer.pkl
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)

# ── Model paths ────────────────────────────────────────────────────────────────
_MODELS_DIR   = Path(__file__).resolve().parent.parent / "models"
_MODEL_PATH   = _MODELS_DIR / "mailforensix_model.pkl"
_VECTOR_PATH  = _MODELS_DIR / "tfidf_vectorizer.pkl"

# ── Module-level singletons (loaded once at startup) ──────────────────────────
_model     = None
_vectorizer = None
_lime_exp   = None
_loaded     = False


# ── Urgency keyword list (used as extra feature) ───────────────────────────────
URGENCY_KEYWORDS = [
    "urgent", "immediately", "verify", "account suspended", "click here",
    "update your", "confirm your", "limited time", "expire", "winner",
    "congratulations", "free", "prize", "password", "login", "bank",
    "wire transfer", "invoice", "payment required", "suspended", "blocked",
    "unusual activity", "security alert", "action required",
]

_URGENCY_RE = re.compile(
    "|".join(re.escape(kw) for kw in URGENCY_KEYWORDS),
    re.IGNORECASE,
)
_URL_RE = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)


def _feature_text(text: str) -> str:
    """Append synthetic tokens for URL count and urgency hits so TF-IDF sees them."""
    url_count  = len(_URL_RE.findall(text))
    urg_count  = len(_URGENCY_RE.findall(text))
    # Append weighted synthetic tokens
    extras  = " URLTOKEN" * min(url_count, 10)
    extras += " URGENCYTOKEN" * min(urg_count, 5)
    return text + extras


def load_model() -> bool:
    """
    Load TF-IDF vectorizer + XGBoost model from disk.
    Safe to call multiple times — loads only once.
    Returns True if models loaded, False if .pkl files missing.
    """
    global _model, _vectorizer, _lime_exp, _loaded

    if _loaded:
        return True

    if not _MODEL_PATH.exists() or not _VECTOR_PATH.exists():
        logger.warning(
            "[classifier] Model .pkl files not found — running in stub mode. "
            "Run: python scripts/train_classifier.py"
        )
        return False

    try:
        import joblib
        from lime.lime_text import LimeTextExplainer

        logger.info("[classifier] Loading TF-IDF vectorizer…")
        _vectorizer = joblib.load(_VECTOR_PATH)

        logger.info("[classifier] Loading XGBoost model…")
        _model = joblib.load(_MODEL_PATH)

        logger.info("[classifier] Initialising LIME explainer…")
        _lime_exp = LimeTextExplainer(class_names=["ham", "phishing"])

        _loaded = True
        logger.info("[classifier] Phase 2 ML models loaded ✓")
        return True

    except Exception as exc:
        logger.error(f"[classifier] Failed to load models: {exc}")
        return False


def model_loaded() -> bool:
    return _loaded


def predict_intent(text: str) -> tuple[str, float]:
    """
    Returns (threat_label, confidence) where threat_label is one of:
      'safe' | 'suspicious' | 'phishing'

    Falls back to heuristic stub when model is not loaded.
    """
    if not _loaded:
        return _heuristic_predict(text)

    try:
        feat = _feature_text(text)
        X    = _vectorizer.transform([feat])
        prob = float(_model.predict_proba(X)[0][1])   # P(phishing)

        if prob >= 0.75:
            label = "phishing"
        elif prob >= 0.45:
            label = "suspicious"
        else:
            label = "safe"

        return label, round(prob, 4)

    except Exception as exc:
        logger.error(f"[classifier] predict_intent error: {exc}")
        return _heuristic_predict(text)


# ── Artifact filter — tokens that are never meaningful explanations ────────────
_ARTIFACT_RE = re.compile(
    r'^(and|or|the|a|an|is|it|in|of|to|for|on|at|by|with|from|this|that|'
    r'be|are|was|were|has|have|had|do|did|not|but|if|as|so|we|you|they|'
    r'he|she|re|cc|bcc|br|hr|td|tr|th|div|span|nbsp|http|https|www|'
    r'[0-9]+|[^a-z]{1,2})$',
    re.IGNORECASE,
)


def _split_sentences(body: str) -> list[str]:
    """
    Split email body into meaningful sentence units.
    Filters out HTML artifacts, very short fragments, and whitespace noise.
    """
    # Strip HTML tags
    clean = re.sub(r'<[^>]+>', ' ', body)
    # Normalize whitespace
    clean = re.sub(r'[ \t]+', ' ', clean)
    # Split on sentence-ending punctuation or newlines
    raw = re.split(r'(?<=[.!?])\s+|\n{1,}', clean)
    sentences = []
    for s in raw:
        s = s.strip()
        # Must be 15+ chars and contain at least 2 words to be a useful sentence
        if len(s) >= 15 and len(s.split()) >= 2:
            sentences.append(s[:200])  # cap length for display
    return sentences


def explain_sentences(body: str, n: int = 8) -> list[dict]:
    """
    Returns list of dicts: [{text, score, explanation}]

    Strategy (Bug 1 + 2 fix):
    1. Split body into REAL sentences (not individual words).
    2. Run LIME with sentence-as-token mode by joining sentences as the
       vocabulary units, using split_expression to preserve them.
    3. Filter out HTML artifacts and stop-words.
    4. Only return PHISHING-POSITIVE items (weight > 0).
    5. Normalize scores relative to the strongest signal found.
    """
    if not _loaded or not body or not body.strip():
        return _heuristic_lime(body, n)

    try:
        sentences = _split_sentences(body)

        # If body doesn't have enough real sentences, fall back to heuristic
        if len(sentences) < 2:
            return _heuristic_lime(body, n)

        # Build a "sentence-tokenized" version of the text for LIME
        # LIME will treat each sentence as a token and perturb by masking them
        sentence_body = "\n".join(sentences)

        # Sentence-level predict function — masks whole sentences, not words
        def _predict_sentence_proba(texts):
            # texts are the perturbed versions (some sentences blanked out)
            X = _vectorizer.transform([_feature_text(t) for t in texts])
            return _model.predict_proba(X)

        from lime.lime_text import LimeTextExplainer
        sent_explainer = LimeTextExplainer(
            class_names=["ham", "phishing"],
            split_expression=r'\n',   # treat each newline-separated sentence as one token
        )

        exp = sent_explainer.explain_instance(
            sentence_body,
            _predict_sentence_proba,
            num_features=min(n + 4, len(sentences)),  # ask for extra, filter after
            num_samples=300,
            labels=(1,),
        )

        raw_list = exp.as_list(label=1)  # [(sentence_text, weight), ...]

        # Filter: keep only phishing-positive, non-artifact entries
        positive = [
            (text.strip(), weight)
            for text, weight in raw_list
            if weight > 0
            and not _ARTIFACT_RE.match(text.strip())
            and len(text.strip()) >= 10
        ]

        if not positive:
            # All signals were negative (ham email) — return top negative with proper label
            all_items = [
                (text.strip(), weight)
                for text, weight in raw_list
                if not _ARTIFACT_RE.match(text.strip())
                and len(text.strip()) >= 10
            ]
            positive = sorted(all_items, key=lambda x: x[1], reverse=True)[:n]

        # Normalize: express each score relative to max weight (0–100%)
        if positive:
            max_weight = max(abs(w) for _, w in positive) or 1.0
        else:
            max_weight = 1.0

        results = []
        for text, weight in sorted(positive, key=lambda x: x[1], reverse=True)[:n]:
            normalized = round(min(abs(weight) / max_weight, 1.0), 4)
            if weight > 0.5:
                explanation = "Strongly indicates phishing"
            elif weight > 0.2:
                explanation = "High phishing signal — key phrase detected"
            elif weight > 0.0:
                explanation = "Moderately suspicious language"
            else:
                explanation = "Reduces phishing probability"

            results.append({
                "text":        text,
                "score":       normalized,
                "explanation": explanation,
            })

        return results if results else _heuristic_lime(body, n)

    except Exception as exc:
        logger.error(f"[classifier] explain_sentences error: {exc}")
        return _heuristic_lime(body, n)


# ── Heuristic fallbacks (when model not loaded) ────────────────────────────────

def _heuristic_predict(text: str) -> tuple[str, float]:
    """Simple keyword + URL heuristic. Used when .pkl not loaded."""
    url_count  = len(_URL_RE.findall(text))
    urg_count  = len(_URGENCY_RE.findall(text))
    score      = min((url_count * 0.05) + (urg_count * 0.08), 0.95)

    if score >= 0.60:
        return "phishing", round(score, 4)
    elif score >= 0.30:
        return "suspicious", round(score, 4)
    return "safe", round(score, 4)


def _heuristic_lime(body: str, n: int) -> list[dict]:
    """Keyword-based sentence highlights. Used when LIME not available."""
    if not body:
        return [{"text": "[no body]", "score": 0.0, "explanation": "Empty email body."}]

    results = []
    sentences = [s.strip() for s in re.split(r"[.!?\n]", body) if len(s.strip()) > 8]
    for sent in sentences[:n]:
        hits = _URGENCY_RE.findall(sent)
        urls = _URL_RE.findall(sent)
        score = min(len(hits) * 0.15 + len(urls) * 0.10, 1.0)
        if hits or urls:
            exp = f"Contains: {', '.join(set(h.lower() for h in hits))}" if hits else f"Contains URL"
        else:
            exp = "No strong phishing signals"
        results.append({"text": sent[:120], "score": round(score, 4), "explanation": exp})

    if not results:
        results.append({"text": body[:120], "score": 0.0, "explanation": "No phishing signals detected."})

    return sorted(results, key=lambda x: x["score"], reverse=True)[:n]
