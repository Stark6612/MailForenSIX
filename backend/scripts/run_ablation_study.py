"""
scripts/run_ablation_study.py
─────────────────────────────
AICS Phase 4.2 — Feature Representation Ablation Study.
Course: Artificial Intelligence for Cyber Security (23AI2001)

Systematically evaluates four feature representation configurations:
  - Setup 1: Bag-of-Words (BoW) Term Frequency Baseline
  - Setup 2: Unigram TF-IDF Representation
  - Setup 3: Sublinear TF-IDF with Unigram + Bigram Collocations
  - Setup 4: Hybrid TF-IDF + Domain Cyber Tokens + Structural Metadata (scipy.sparse.hstack)

Outputs:
  - backend/proof/aics/aics_ablation_results.json
  - backend/proof/aics/aics_feature_ablation.png
"""

import os
import re
import sys
import json
import time
from pathlib import Path
from typing import Dict, List, Tuple

os.environ["LOKY_MAX_CPU_COUNT"] = "1"

import joblib
import numpy as np
import pandas as pd
import scipy.sparse as sp
import matplotlib.pyplot as plt
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).resolve().parent.parent
DATA_DIR    = BASE_DIR / "data"
PROOF_AICS  = BASE_DIR / "proof" / "aics"
PROOF_AICS.mkdir(parents=True, exist_ok=True)

PARQUET_PATH = DATA_DIR / "aics_corpus_3class.parquet"
OUT_JSON     = PROOF_AICS / "aics_ablation_results.json"
OUT_PNG      = PROOF_AICS / "aics_feature_ablation.png"

# ── Feature Extraction Regex ───────────────────────────────────────────────────
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


def extract_structural_features(texts: List[str]) -> np.ndarray:
    """Extracts dense continuous structural metadata vectors."""
    dense_feats = []
    for t in texts:
        if not isinstance(t, str):
            t = ""
        char_len  = len(t)
        words     = t.split()
        word_cnt  = len(words)
        
        n_url     = len(_URL_RE.findall(t))
        n_ip      = len(_IP_RE.findall(t))
        n_curr    = len(_CURRENCY_RE.findall(t))
        n_urg     = len(_URGENCY_RE.findall(t))
        n_upper   = sum(1 for c in t if c.isupper())
        n_digits  = sum(1 for c in t if c.isdigit())

        upper_ratio = n_upper / (char_len + 1)
        digit_ratio = n_digits / (char_len + 1)

        dense_feats.append([
            n_url,
            n_ip,
            n_curr,
            n_urg,
            char_len / 1000.0,
            word_cnt / 100.0,
            upper_ratio,
            digit_ratio
        ])
    return np.array(dense_feats, dtype=np.float32)


def run_ablation():
    print(f"[1/5] Loading 3-class corpus from {PARQUET_PATH.name}...")
    df = pd.read_parquet(PARQUET_PATH)
    texts  = df["text"].tolist()
    labels = df["label"].values

    # Stratified split: 80% train / 20% test
    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        texts, labels, test_size=0.20, random_state=42, stratify=labels
    )
    print(f"  [OK] Train: {len(X_train_raw)} samples | Test: {len(X_test_raw)} samples")

    configurations = [
        {
            "id": "setup_1_bow",
            "name": "Setup 1: Bag-of-Words (BoW)",
            "description": "Raw unigram term frequencies (CountVectorizer, max_features=10,000)",
            "vectorizer": CountVectorizer(max_features=10000, stop_words="english", ngram_range=(1, 1)),
            "use_structural": False,
        },
        {
            "id": "setup_2_tfidf_unigram",
            "name": "Setup 2: TF-IDF (Unigram)",
            "description": "Term Frequency-Inverse Document Frequency unigrams (max_features=10,000)",
            "vectorizer": TfidfVectorizer(max_features=10000, stop_words="english", ngram_range=(1, 1)),
            "use_structural": False,
        },
        {
            "id": "setup_3_tfidf_bigram",
            "name": "Setup 3: TF-IDF (Unigram + Bigram)",
            "description": "Sublinear TF-IDF with (1, 2) n-grams capturing phishing phrases",
            "vectorizer": TfidfVectorizer(max_features=10000, stop_words="english", ngram_range=(1, 2), sublinear_tf=True),
            "use_structural": False,
        },
        {
            "id": "setup_4_hybrid_structural",
            "name": "Setup 4: Hybrid (TF-IDF + Structural Metadata)",
            "description": "Sublinear (1,2) TF-IDF concatenated with 8 dense structural cyber cues via scipy.sparse.hstack",
            "vectorizer": TfidfVectorizer(max_features=10000, stop_words="english", ngram_range=(1, 2), sublinear_tf=True),
            "use_structural": True,
        },
    ]

    results = []
    base_f1 = None

    print("\n[2/5] Evaluating feature representation configurations...")
    for idx, cfg in enumerate(configurations):
        print(f"\n  Running {cfg['name']}...")
        vec = cfg["vectorizer"]
        
        t0 = time.time()
        X_tr = vec.fit_transform(X_train_raw)
        X_te = vec.transform(X_test_raw)

        if cfg["use_structural"]:
            print("    Concatenating dense structural features via scipy.sparse.hstack...")
            struct_tr = extract_structural_features(X_train_raw)
            struct_te = extract_structural_features(X_test_raw)

            scaler = StandardScaler()
            struct_tr_scaled = scaler.fit_transform(struct_tr)
            struct_te_scaled = scaler.transform(struct_te)

            X_tr = sp.hstack([X_tr, sp.csr_matrix(struct_tr_scaled)], format="csr")
            X_te = sp.hstack([X_te, sp.csr_matrix(struct_te_scaled)], format="csr")

        feat_dim = X_tr.shape[1]

        # Train Logistic Regression
        clf = LogisticRegression(C=1.0, max_iter=1000, random_state=42)
        clf.fit(X_tr, y_train)

        train_time = round(time.time() - t0, 3)

        # Evaluate
        preds = clf.predict(X_te)
        acc = accuracy_score(y_test, preds)
        prec, rec, f1, _ = precision_recall_fscore_support(y_test, preds, average="macro")

        if base_f1 is None:
            base_f1 = f1
            delta_f1 = 0.0
        else:
            delta_f1 = f1 - base_f1

        print(f"    Feature Dim: {feat_dim} | Time: {train_time}s")
        print(f"    Accuracy:    {acc*100:.2f}%")
        print(f"    Macro F1:    {f1:.4f} (Delta F1: {delta_f1:+.4f})")
        print(f"    Macro Prec:  {prec:.4f} | Macro Rec: {rec:.4f}")

        results.append({
            "setup_id": cfg["id"],
            "name": cfg["name"],
            "description": cfg["description"],
            "feature_dimension": int(feat_dim),
            "train_time_sec": train_time,
            "accuracy": round(float(acc), 4),
            "macro_precision": round(float(prec), 4),
            "macro_recall": round(float(rec), 4),
            "macro_f1": round(float(f1), 4),
            "delta_f1_vs_baseline": round(float(delta_f1), 4)
        })

    print(f"\n[3/5] Saving ablation benchmark results to {OUT_JSON}...")
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print("  [OK] Saved JSON.")

    print("\n[4/5] Plotting publication-quality feature ablation chart...")
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5), constrained_layout=True)

    labels = ["BoW (Count)", "TF-IDF (1-gram)", "TF-IDF (1-2 gram)", "Hybrid + Struct"]
    x = np.arange(len(labels))
    width = 0.20

    accs  = [r["accuracy"] * 100 for r in results]
    precs = [r["macro_precision"] * 100 for r in results]
    recs  = [r["macro_recall"] * 100 for r in results]
    f1s   = [r["macro_f1"] * 100 for r in results]

    b1 = ax1.bar(x - 1.5*width, accs,  width, label="Accuracy (%)",  color="#2563eb", edgecolor="#1e293b")
    b2 = ax1.bar(x - 0.5*width, precs, width, label="Precision (%)", color="#059669", edgecolor="#1e293b")
    b3 = ax1.bar(x + 0.5*width, recs,  width, label="Recall (%)",    color="#d97706", edgecolor="#1e293b")
    b4 = ax1.bar(x + 1.5*width, f1s,   width, label="Macro F1 (%)",  color="#7c3aed", edgecolor="#1e293b")

    ax1.set_title("Ablation: Metric Progression across Feature Representations", fontsize=11, fontweight="bold")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, fontsize=9.5, fontweight="semibold")
    ax1.set_ylim(85, 96)
    ax1.set_ylabel("Score (%)", fontsize=10)
    ax1.grid(axis="y", linestyle="--", alpha=0.4)
    ax1.legend(loc="lower right", framealpha=0.9)

    # Delta F1 Bar Plot
    deltas = [r["delta_f1_vs_baseline"] * 100 for r in results]
    delta_colors = ["#64748b", "#0284c7", "#059669", "#7c3aed"]
    bars_delta = ax2.bar(labels, deltas, color=delta_colors, width=0.45, edgecolor="#1e293b", linewidth=1.0)
    ax2.set_title("Incremental Gain over Baseline (Delta Macro F1 %)", fontsize=11, fontweight="bold")
    ax2.set_ylabel("Gain over BoW (Percentage Points)", fontsize=10)
    ax2.grid(axis="y", linestyle="--", alpha=0.4)
    ax2.axhline(0, color="#1e293b", linewidth=1)

    for bar, d in zip(bars_delta, deltas):
        yval = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2, yval + (0.05 if yval >= 0 else -0.15),
                 f"{yval:+.2f}%", ha="center", va="bottom" if yval >= 0 else "top",
                 fontsize=10, fontweight="bold")

    fig.suptitle("AICS Empirical Feature Ablation Study (Module 1 & 2 Optimization)", fontsize=13, fontweight="bold")
    fig.savefig(OUT_PNG, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"  [OK] Saved ablation plot to {OUT_PNG}")

    print("\n[5/5] Feature Ablation Summary Table:")
    print("=" * 80)
    print(f"{'Configuration':<35} | {'Feats':<6} | {'Accuracy':<9} | {'Macro F1':<9} | {'Delta F1':<8}")
    print("-" * 80)
    for r in results:
        print(f"{r['name']:<35} | {r['feature_dimension']:<6} | {r['accuracy']*100:>7.2f}% | {r['macro_f1']:>8.4f} | {r['delta_f1_vs_baseline']:>+7.4f}")
    print("=" * 80)
    print("[ALL DONE] Phase 4.2 Ablation Study Complete!")


if __name__ == "__main__":
    run_ablation()

