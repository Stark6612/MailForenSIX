"""
scripts/run_aics_lime.py
────────────────────────
AICS Phase 4 — Multi-Class Explainable AI (LIME) Attributions.
Course: Artificial Intelligence for Cyber Security (23AI2001)

Implements local surrogate explainability across all 3 target classes:
  - Class 0: Legitimate (Corporate / Personal)
  - Class 1: Spam (Unsolicited bulk marketing / Commercial)
  - Class 2: Phishing (Credential harvesting / BEC wire fraud)

Mathematical Formulation (Ribeiro et al., 2016; Pan & Mishra, 2023):
  \\xi(x) = argmin_{g in G} L(f, g, \\pi_x) + \\Omega(g)

Generates:
  - backend/proof/aics/aics_lime_attribution.png
  - backend/proof/aics/aics_lime_explanations.json
"""

import os
import re
import sys
import json
from pathlib import Path
from typing import List, Dict

os.environ["LOKY_MAX_CPU_COUNT"] = "1"

import joblib
import numpy as np
import matplotlib.pyplot as plt
from lime.lime_text import LimeTextExplainer

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).resolve().parent.parent
MODELS_AICS = BASE_DIR / "models" / "aics"
PROOF_AICS  = BASE_DIR / "proof" / "aics"
PROOF_AICS.mkdir(parents=True, exist_ok=True)

VECTOR_PATH = MODELS_AICS / "aics_tfidf_vectorizer.pkl"
LR_PATH     = MODELS_AICS / "lr.pkl"
SVM_PATH    = MODELS_AICS / "svm.pkl"
XGB_PATH    = MODELS_AICS / "xgb.pkl"

OUT_PNG     = PROOF_AICS / "aics_lime_attribution.png"
OUT_JSON    = PROOF_AICS / "aics_lime_explanations.json"

CLASS_NAMES = ["Legitimate", "Spam", "Phishing"]

# ── Domain Preprocessor ────────────────────────────────────────────────────────
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


def preprocess_text(text: str) -> str:
    """Standardizes input email text and maps synthetic domain tokens."""
    if not isinstance(text, str) or not text.strip():
        return ""
    clean = _HTML_TAG_RE.sub(" ", text)
    clean = _URL_RE.sub(" URL_TOKEN ", clean)
    clean = _IP_RE.sub(" IP_TOKEN ", clean)
    clean = _CURRENCY_RE.sub(" CURRENCY_TOKEN ", clean)
    clean = _URGENCY_RE.sub(" URGENCY_TOKEN ", clean)
    clean = re.sub(r"\s+", " ", clean).strip().lower()
    return clean


# ── Canonical Test Samples ─────────────────────────────────────────────────────
TEST_SAMPLES = [
    {
        "id": "SAMPLE_PHISHING",
        "category": "Credential Phishing & Security Alert",
        "ground_truth": 2,
        "text": (
            "Mail Security Team: Dear user, most of your incoming mailbox messages are on pending status "
            "due to mail session expiration issues. Action required: Please click here to verify your identity "
            "and confirm your account credentials immediately to prevent mailbox deactivation: "
            "http://mail-security-verification.org/login. Unauthorized access has been detected."
        )
    },
    {
        "id": "SAMPLE_SPAM",
        "category": "Commercial Marketing Spam",
        "ground_truth": 1,
        "text": (
            "CONGRATULATIONS! You have been selected to win a free $5,000 cash voucher and luxury gift card. "
            "Limited time discount offer for approved subscribers! Claim your exclusive prize today. "
            "Visit our retail shopping bonus site: http://best-deals-super-promo.org/claim. "
            "No credit check required. Unsubscribe at any time."
        )
    },
    {
        "id": "SAMPLE_LEGITIMATE",
        "category": "Legitimate Corporate Communication",
        "ground_truth": 0,
        "text": (
            "Hi team, please find attached the quarterly financial summary report and meeting minutes "
            "from yesterday's project alignment review. We have finalized the sprint deliverables for Q4. "
            "Please review the slide deck on the internal company drive and let me know if you have "
            "any questions before Friday's standup."
        )
    }
]


def run_lime_attribution():
    print("[1/4] Loading vectorizer and calibrated models...")
    vectorizer = joblib.load(VECTOR_PATH)
    lr_model   = joblib.load(LR_PATH)
    svm_model  = joblib.load(SVM_PATH)
    xgb_model  = joblib.load(XGB_PATH)

    # Primary explainer model: Logistic Regression (highest calibration & interpretability)
    primary_model = lr_model
    model_name = "Logistic Regression (L2 Calibrated)"

    print(f"  [OK] Explaining decision surface for {model_name}")

    def predict_probabilities(texts: List[str]) -> np.ndarray:
        cleaned = [preprocess_text(t) for t in texts]
        X = vectorizer.transform(cleaned)
        return primary_model.predict_proba(X)

    print("[2/4] Initializing LimeTextExplainer with multi-class surrogate...")
    explainer = LimeTextExplainer(
        class_names=CLASS_NAMES,
        bow=True,
        split_expression=r"\W+",
        random_state=42
    )

    results = []
    
    print("[3/4] Generating LIME perturbations and local ridge regressions...")
    for idx, sample in enumerate(TEST_SAMPLES):
        text = sample["text"]
        cat  = sample["category"]
        gt   = sample["ground_truth"]

        probs = predict_probabilities([text])[0]
        pred_class = int(np.argmax(probs))
        pred_label = CLASS_NAMES[pred_class]
        confidence = float(probs[pred_class])

        print(f"\n  Email {idx+1}: {cat}")
        print(f"    Predicted: {pred_label} ({confidence:.4f}) | Ground Truth: {CLASS_NAMES[gt]}")

        # Explain prediction with LIME (num_features=8, num_samples=1000)
        exp = explainer.explain_instance(
            text,
            predict_probabilities,
            labels=[0, 1, 2],
            num_features=8,
            num_samples=1000
        )

        class_weights = {}
        for c in range(3):
            class_name = CLASS_NAMES[c]
            weights = exp.as_list(label=c)
            class_weights[class_name] = [
                {"token": w[0], "weight": round(float(w[1]), 5)}
                for w in weights
            ]

        results.append({
            "sample_id": sample["id"],
            "category": cat,
            "text": text,
            "ground_truth": CLASS_NAMES[gt],
            "prediction": pred_label,
            "probabilities": {
                CLASS_NAMES[c]: round(float(probs[c]), 4) for c in range(3)
            },
            "lime_attributions": class_weights
        })

    # Save JSON summary
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\n  [OK] Saved attribution data to {OUT_JSON}")

    # Plot Visualizations
    print("[4/4] Rendering publication-quality LIME attribution charts...")
    fig, axes = plt.subplots(3, 1, figsize=(11, 13), constrained_layout=True)

    for i, res in enumerate(results):
        ax = axes[i]
        pred_cls = res["prediction"]
        weights = res["lime_attributions"][pred_cls][:7]  # top 7 features

        tokens = [w["token"] for w in weights][::-1]
        vals   = [w["weight"] for w in weights][::-1]
        colors = ["#dc2626" if v > 0 else "#2563eb" for v in vals]

        bars = ax.barh(tokens, vals, color=colors, height=0.55, edgecolor="#1e293b", linewidth=0.8)
        
        # Labels and styling
        ax.set_title(
            f"Sample {i+1} ({res['category']})\n"
            f"Prediction: {pred_cls.upper()} (P = {res['probabilities'][pred_cls]:.3f}) | "
            f"Ground Truth: {res['ground_truth']}",
            fontsize=11, fontweight="bold", pad=8
        )
        ax.set_xlabel("Local Surrogate Linear Weight (Directional Impact)", fontsize=9.5)
        ax.grid(axis="x", linestyle="--", alpha=0.4)
        ax.axvline(0, color="#64748b", linewidth=1.2)

        # Annotate values
        for bar in bars:
            val = bar.get_width()
            offset = 0.005 if val >= 0 else -0.015
            ax.text(val + offset, bar.get_y() + bar.get_height()/2, f"{val:+.3f}",
                    va="center", ha="left" if val >= 0 else "right", fontsize=8.5, fontweight="semibold")

    fig.suptitle(
        "AICS Multi-Class LIME Feature Attributions (Local Surrogate Linear Explanations)\n"
        "Model: Regularized Multi-Class Classifier | Course: 23AI2001",
        fontsize=13, fontweight="bold", y=1.02
    )

    fig.savefig(OUT_PNG, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"  [OK] Saved LIME visualization figure to {OUT_PNG}")
    print("[ALL DONE] Phase 4.1 LIME Module Complete!")


if __name__ == "__main__":
    run_lime_attribution()
