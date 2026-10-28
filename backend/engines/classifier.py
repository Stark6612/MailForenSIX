"""
engines/classifier.py — Phase 2 & Phase 6 (AICS Multi-Model Dynamic Registry)
Course: Artificial Intelligence for Cyber Security (23AI2001)

Features:
  - Multi-Model Dynamic Registry supporting:
      * lr:  Logistic Regression (L2 Regularized Log-Odds)
      * svm: Linear Support Vector Machine (Platt Calibrated)
      * nb:  Multinomial Naive Bayes (Laplace Smoothed)
      * dt:  Decision Tree (CART Gini Impurity)
      * xgb: HistGradientBoosting Ensemble
  - Tripartite 3-Class Classification:
      * Class 0: Legitimate (Ham)
      * Class 1: Spam (Commercial / Bulk)
      * Class 2: Phishing (Credential Harvesting / BEC Fraud)
  - Multi-Class Explainable AI (LIME) Local Surrogate Sentence Attributions.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional

logger = logging.getLogger(__name__)

# ── Paths ──────────────────────────────────────────────────────────────────────
_MODELS_DIR     = Path(__file__).resolve().parent.parent / "models"
_AICS_DIR       = _MODELS_DIR / "aics"
_LEGACY_MODEL   = _MODELS_DIR / "mailforensix_model.pkl"
_LEGACY_VECTOR  = _MODELS_DIR / "tfidf_vectorizer.pkl"

_AICS_VECTOR    = _AICS_DIR / "aics_tfidf_vectorizer.pkl"

MODEL_METADATA = {
    "lr": {
        "id": "lr",
        "name": "Logistic Regression (L2 Calibrated)",
        "type": "Generalized Linear Model",
        "description": "L2-regularized multinomial logistic regression with cross-entropy loss."
    },
    "svm": {
        "id": "svm",
        "name": "Linear SVM (Platt Calibrated)",
        "type": "Maximum Margin Separator",
        "description": "L2-regularized linear support vector machine with Platt sigmoid calibration."
    },
    "nb": {
        "id": "nb",
        "name": "Multinomial Naive Bayes",
        "type": "Generative Probabilistic",
        "description": "Multinomial Bayes with Laplace additive smoothing (alpha=0.1)."
    },
    "dt": {
        "id": "dt",
        "name": "Decision Tree (CART Gini)",
        "type": "Non-Parametric Partitioning",
        "description": "Binary recursive partition tree using Gini impurity criterion."
    },
    "xgb": {
        "id": "xgb",
        "name": "HistGradientBoosting Ensemble",
        "type": "Ensemble Gradient Boosting",
        "description": "Histogram-based gradient boosted decision tree ensemble."
    }
}

CLASS_NAMES_3 = ["legitimate", "spam", "phishing"]

# ── Module Singletons ──────────────────────────────────────────────────────────
_models_registry: Dict[str, any] = {}
_vectorizer = None
_loaded = False
_legacy_model = None
_legacy_vectorizer = None


# ── Domain-Specific Token Preprocessing ────────────────────────────────────────
_HTML_TAG_RE = re.compile(r"<[^>]+>", re.IGNORECASE)
_URL_RE      = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)
_IP_RE       = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_CURRENCY_RE = re.compile(r"[\$€£₹]\s*\d+(?:[.,]\d+)?|\b(?:usd|eur|inr|gbp|dollars?)\s*\d+\b", re.IGNORECASE)
URGENCY_KEYWORDS = [
    r"\burgent\b", r"\bimmediately\b", r"\bverify your\b", r"\baccount suspended\b",
    r"\baction required\b", r"\bsecurity alert\b", r"\bunauthorized access\b",
    r"\bconfirm your identity\b", r"\bclick here\b", r"\breset your password\b",
    r"\blimited time\b", r"\bwire transfer\b", r"\bpayment overdue\b",
    r"\bupdate payment\b", r"\bbank account\b", r"\blogin immediately\b",
]
_URGENCY_RE  = re.compile("|".join(URGENCY_KEYWORDS), re.IGNORECASE)


def _preprocess_aics(text: str) -> str:
    """Preprocess email text and inject synthetic domain cyber tokens."""
    if not isinstance(text, str) or not text.strip():
        return ""
    clean = _HTML_TAG_RE.sub(" ", text)
    clean = _URL_RE.sub(" URL_TOKEN ", clean)
    clean = _IP_RE.sub(" IP_TOKEN ", clean)
    clean = _CURRENCY_RE.sub(" CURRENCY_TOKEN ", clean)
    clean = _URGENCY_RE.sub(" URGENCY_TOKEN ", clean)
    return re.sub(r"\s+", " ", clean).strip().lower()


def load_model() -> bool:
    """
    Load AICS multi-model suite and fallback vectorizers.
    Safe to call multiple times (cached).
    """
    global _models_registry, _vectorizer, _legacy_model, _legacy_vectorizer, _loaded

    if _loaded:
        return True

    import joblib

    # 1. Try loading AICS 3-Class Models
    if _AICS_VECTOR.exists():
        try:
            logger.info("[classifier] Loading AICS TF-IDF Vectorizer...")
            _vectorizer = joblib.load(_AICS_VECTOR)

            for mid in ["lr", "svm", "nb", "dt", "xgb"]:
                mpath = _AICS_DIR / f"{mid}.pkl"
                if mpath.exists():
                    logger.info(f"[classifier] Loading AICS model: {mid} ({MODEL_METADATA[mid]['name']})...")
                    _models_registry[mid] = joblib.load(mpath)

            if _models_registry:
                _loaded = True
                logger.info(f"[classifier] Successfully loaded {len(_models_registry)} AICS models.")
        except Exception as exc:
            logger.error(f"[classifier] Error loading AICS models: {exc}")

    # 2. Try loading legacy model if available as fallback
    if _LEGACY_MODEL.exists() and _LEGACY_VECTOR.exists():
        try:
            _legacy_vectorizer = joblib.load(_LEGACY_VECTOR)
            _legacy_model      = joblib.load(_LEGACY_MODEL)
            if not _loaded:
                _loaded = True
        except Exception as exc:
            logger.warning(f"[classifier] Error loading legacy model: {exc}")

    return _loaded


def model_loaded() -> bool:
    return _loaded


def get_available_models() -> List[Dict]:
    """Returns list of active models in registry."""
    available = []
    for mid, meta in MODEL_METADATA.items():
        if mid in _models_registry:
            available.append(meta)
    return available


def predict_intent(
    text: str,
    model_id: str = "lr"
) -> Tuple[str, float, Dict[str, float], str]:
    """
    Executes tripartite intent prediction using the requested model.
    Returns:
      (threat_label: str, confidence: float, class_probs: dict, model_name: str)
      where threat_label is 'safe' (legitimate), 'spam', or 'phishing'.
    """
    if not _loaded:
        label, conf = _heuristic_predict(text)
        return label, conf, {label: conf}, "Heuristic Stub Engine"

    # Select model from registry
    target_id = model_id.lower() if model_id and model_id.lower() in _models_registry else "lr"
    model = _models_registry.get(target_id)
    meta  = MODEL_METADATA.get(target_id, {"name": "Default Classifier"})

    if model is None and _legacy_model is not None:
        # Fallback to legacy binary model
        try:
            X = _legacy_vectorizer.transform([text])
            prob = float(_legacy_model.predict_proba(X)[0][1])
            lbl = "phishing" if prob >= 0.70 else ("suspicious" if prob >= 0.40 else "safe")
            return lbl, round(prob, 4), {"phishing": prob, "safe": 1 - prob}, "Legacy XGBoost"
        except Exception:
            label, conf = _heuristic_predict(text)
            return label, conf, {label: conf}, "Heuristic Stub Engine"

    if model is None:
        label, conf = _heuristic_predict(text)
        return label, conf, {label: conf}, "Heuristic Stub Engine"

    try:
        clean = _preprocess_aics(text)
        X     = _vectorizer.transform([clean])

        if isinstance(model, dict) and "model" in model and "selector" in model:
            X_dense = model["selector"].transform(X).toarray()
            probs = model["model"].predict_proba(X_dense)[0]
        else:
            probs = model.predict_proba(X)[0]

        p_legit = float(probs[0])
        p_spam  = float(probs[1])
        p_phish = float(probs[2])

        class_probs = {
            "legitimate": round(p_legit, 4),
            "spam":       round(p_spam, 4),
            "phishing":   round(p_phish, 4),
        }

        # Argmax selection
        max_idx = int(probs.argmax())
        confidence = round(float(probs[max_idx]), 4)

        if max_idx == 2:
            threat_label = "phishing"
        elif max_idx == 1:
            threat_label = "spam"
        else:
            threat_label = "safe"

        return threat_label, confidence, class_probs, meta["name"]

    except Exception as exc:
        logger.error(f"[classifier] predict_intent error ({target_id}): {exc}")
        label, conf = _heuristic_predict(text)
        return label, conf, {label: conf}, "Heuristic Stub Engine"


def _split_sentences(body: str) -> List[str]:
    """Split email body into semantic sentence segments."""
    clean = _HTML_TAG_RE.sub(" ", body)
    clean = re.sub(r"[ \t]+", " ", clean)
    raw = re.split(r"(?<=[.!?])\s+|\n{1,}", clean)
    sentences = []
    for s in raw:
        s = s.strip()
        if len(s) >= 12 and len(s.split()) >= 2:
            sentences.append(s[:220])
    return sentences


def explain_sentences(
    body: str,
    model_id: str = "lr",
    n: int = 8
) -> List[Dict]:
    """
    Generates multi-class LIME sentence-level explanations.
    Surfaces the exact sentence units driving the threat prediction.
    """
    if not _loaded or not body or not body.strip():
        return _heuristic_lime(body, n)

    target_id = model_id.lower() if model_id and model_id.lower() in _models_registry else "lr"
    model = _models_registry.get(target_id)
    if model is None:
        return _heuristic_lime(body, n)

    try:
        sentences = _split_sentences(body)
        if len(sentences) < 2:
            return _heuristic_lime(body, n)

        sentence_body = "\n".join(sentences)

        def _predict_sentence_proba(texts):
            cleaned = [_preprocess_aics(t) for t in texts]
            X = _vectorizer.transform(cleaned)
            if isinstance(model, dict) and "model" in model and "selector" in model:
                X_dense = model["selector"].transform(X).toarray()
                return model["model"].predict_proba(X_dense)
            return model.predict_proba(X)

        from lime.lime_text import LimeTextExplainer
        sent_explainer = LimeTextExplainer(
            class_names=CLASS_NAMES_3,
            split_expression=r"\n",
            random_state=42
        )

        # Explain the dominant predicted class
        probs = _predict_sentence_proba([sentence_body])[0]
        top_class = int(probs.argmax())

        exp = sent_explainer.explain_instance(
            sentence_body,
            _predict_sentence_proba,
            labels=(top_class,),
            num_features=min(n + 3, len(sentences)),
            num_samples=180
        )

        raw_list = exp.as_list(label=top_class)
        if not raw_list:
            return _heuristic_lime(body, n)

        max_weight = max(abs(w[1]) for w in raw_list) or 1.0

        results = []
        for text, weight in sorted(raw_list, key=lambda x: abs(x[1]), reverse=True)[:n]:
            norm_score = round(min(abs(weight) / max_weight, 1.0), 4)
            if top_class == 2:  # Phishing
                exp_text = "Strongly indicates credential phishing" if weight > 0 else "Mitigates phishing risk"
            elif top_class == 1:  # Spam
                exp_text = "Commercial marketing / bulk spam trigger" if weight > 0 else "Neutral phrase"
            else:
                exp_text = "Legitimate business phrasing" if weight > 0 else "Unusual phrasing"

            results.append({
                "text": text.strip(),
                "score": norm_score,
                "explanation": exp_text
            })

        return results if results else _heuristic_lime(body, n)

    except Exception as exc:
        logger.error(f"[classifier] explain_sentences error: {exc}")
        return _heuristic_lime(body, n)


# ── Heuristic Fallback Methods ─────────────────────────────────────────────────

def _heuristic_predict(text: str) -> Tuple[str, float]:
    url_count  = len(_URL_RE.findall(text))
    urg_count  = len(_URGENCY_RE.findall(text))
    score      = min((url_count * 0.08) + (urg_count * 0.12), 0.95)
    if score >= 0.60:
        return "phishing", round(score, 4)
    elif score >= 0.30:
        return "spam", round(score, 4)
    return "safe", round(score, 4)


def _heuristic_lime(body: str, n: int) -> List[Dict]:
    if not body:
        return [{"text": "[no body]", "score": 0.0, "explanation": "Empty email body."}]
    results = []
    sentences = [s.strip() for s in re.split(r"[.!?\n]", body) if len(s.strip()) > 8]
    for sent in sentences[:n]:
        hits = _URGENCY_RE.findall(sent)
        urls = _URL_RE.findall(sent)
        score = min(len(hits) * 0.20 + len(urls) * 0.15, 1.0)
        exp = f"Urgency cue: {', '.join(set(h.lower() for h in hits))}" if hits else ("Contains URL link" if urls else "Benign phrasing")
        results.append({"text": sent[:120], "score": round(score, 4), "explanation": exp})
    if not results:
        results.append({"text": body[:120], "score": 0.0, "explanation": "No threat signals identified."})
    return sorted(results, key=lambda x: x["score"], reverse=True)[:n]
