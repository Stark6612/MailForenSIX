"""
backend/scripts/train_aics_models.py
────────────────────────────────────
AICS Phase 2 — Multi-Model Algorithmic Training & Comparative Benchmark.
Course: Artificial Intelligence for Cyber Security (23AI2001)

Trains and evaluates 5 distinct ML algorithms on the identical 3-Class Corpus:
  1. Multinomial Naive Bayes (Generative probabilistic)
  2. Linear Support Vector Machine (Max-margin linear)
  3. Logistic Regression (L2 regularized log-odds)
  4. Decision Tree (Non-parametric CART)
  5. Gradient Boosted Trees (Ensemble boosting)

Outputs:
  - backend/models/aics/*.pkl (serialized models)
  - backend/proof/aics/aics_model_benchmark.json (empirical metrics)
  - backend/proof/aics/aics_benchmark_table.md (markdown comparison table)
"""

import os
os.environ["LOKY_MAX_CPU_COUNT"] = "1"

import sys
import time
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import HistGradientBoostingClassifier

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).resolve().parent.parent
DATA_PARQUET = BASE_DIR / "data" / "aics_corpus_3class.parquet"
VECTOR_PATH  = BASE_DIR / "models" / "aics" / "aics_tfidf_vectorizer.pkl"
MODELS_AICS  = BASE_DIR / "models" / "aics"
PROOF_AICS   = BASE_DIR / "proof" / "aics"

MODELS_AICS.mkdir(parents=True, exist_ok=True)
PROOF_AICS.mkdir(parents=True, exist_ok=True)

OUT_BENCHMARK_JSON = PROOF_AICS / "aics_model_benchmark.json"
OUT_BENCHMARK_MD   = PROOF_AICS / "aics_benchmark_table.md"


def main():
    print("=" * 70)
    print("AICS Phase 2 — Multi-Model Training & Benchmark Suite")
    print("=" * 70)

    if not DATA_PARQUET.exists() or not VECTOR_PATH.exists():
        print(f"[ERROR] Required Phase 1 artifacts not found.")
        sys.exit(1)

    print(f"[LOAD] Loading corpus from {DATA_PARQUET}...")
    df = pd.read_parquet(DATA_PARQUET)
    vectorizer = joblib.load(VECTOR_PATH)

    print(f"  Total samples: {len(df):,} across 3 classes")

    # Split identical to Phase 1
    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        df["text"],
        df["label"],
        test_size=0.20,
        random_state=42,
        stratify=df["label"],
    )

    print(f"[VECTORIZATION] Transforming raw texts into TF-IDF sparse matrices...")
    t0 = time.time()
    X_train = vectorizer.transform(X_train_raw)
    X_test  = vectorizer.transform(X_test_raw)
    print(f"  Feature shape: {X_train.shape} in {time.time() - t0:.2f}s")

    # Model definitions aligned with Syllabus Module 2
    models_config = {
        "Multinomial_Naive_Bayes": {
            "name": "Multinomial Naive Bayes",
            "syllabus_ref": "Module 2: Spam Detection with Naive Bayes",
            "model": MultinomialNB(alpha=0.1),
            "file": MODELS_AICS / "nb.pkl",
            "requires_dense": False,
        },
        "Support_Vector_Machine": {
            "name": "Linear SVM",
            "syllabus_ref": "Module 2: Spam Detection with SVMs",
            "model": LinearSVC(C=1.0, dual=False, max_iter=2000, random_state=42),
            "file": MODELS_AICS / "svm.pkl",
            "requires_dense": False,
        },
        "Logistic_Regression": {
            "name": "Logistic Regression (L2)",
            "syllabus_ref": "Module 2: Phishing Detection with Logistic Regression",
            "model": LogisticRegression(C=2.0, max_iter=1000, random_state=42),
            "file": MODELS_AICS / "lr.pkl",
            "requires_dense": False,
        },
        "Decision_Tree": {
            "name": "Decision Tree (CART)",
            "syllabus_ref": "Module 2: Phishing Detection with Decision Trees",
            "model": DecisionTreeClassifier(max_depth=35, min_samples_split=5, random_state=42),
            "file": MODELS_AICS / "dt.pkl",
            "requires_dense": False,
        },
        "Gradient_Boosted_Trees": {
            "name": "Gradient Boosted Trees (HistGB)",
            "syllabus_ref": "Module 2: Ensemble & Tree Threat Detectors",
            "model": HistGradientBoostingClassifier(max_iter=150, max_depth=8, learning_rate=0.1, random_state=42),
            "file": MODELS_AICS / "xgb.pkl",
            "requires_dense": True,
        },
    }

    benchmark_results = {}
    label_names = ["Legitimate", "Spam", "Phishing"]

    for model_key, cfg in models_config.items():
        print(f"\n[TRAIN] Training {cfg['name']} ({cfg['syllabus_ref']})...")
        model = cfg["model"]

        t_start = time.time()
        if cfg["requires_dense"]:
            # For HistGradientBoosting, select top 1000 features for fast tree binning
            from sklearn.feature_selection import SelectKBest, chi2
            selector = SelectKBest(chi2, k=min(1000, X_train.shape[1]))
            X_tr_dense = selector.fit_transform(X_train, y_train).toarray()
            X_te_dense = selector.transform(X_test).toarray()
            model.fit(X_tr_dense, y_train)
            train_time = time.time() - t_start

            # Benchmark inference
            t_inf_start = time.time()
            y_pred = model.predict(X_te_dense)
            inf_time = (time.time() - t_inf_start) / len(y_test) * 1e6  # microseconds
            
            # Save pipeline with selector
            joblib.dump({"selector": selector, "model": model}, cfg["file"])
        else:
            model.fit(X_train, y_train)
            train_time = time.time() - t_start

            # Benchmark inference
            t_inf_start = time.time()
            y_pred = model.predict(X_test)
            inf_time = (time.time() - t_inf_start) / len(y_test) * 1e6  # microseconds

            joblib.dump(model, cfg["file"])

        # Calculate metrics
        acc = accuracy_score(y_test, y_pred)
        prec_macro = precision_score(y_test, y_pred, average="macro")
        rec_macro  = recall_score(y_test, y_pred, average="macro")
        f1_macro   = f1_score(y_test, y_pred, average="macro")
        f1_weighted = f1_score(y_test, y_pred, average="weighted")

        # Per-class F1
        per_class_f1 = f1_score(y_test, y_pred, average=None)
        cm = confusion_matrix(y_test, y_pred).tolist()

        file_size_kb = cfg["file"].stat().st_size / 1024

        print(f"  -> Accuracy: {acc*100:.2f}% | Macro F1: {f1_macro:.4f} | Latency: {inf_time:.1f} us/sample | Size: {file_size_kb:.1f} KB")

        benchmark_results[model_key] = {
            "name": cfg["name"],
            "syllabus_ref": cfg["syllabus_ref"],
            "accuracy": round(float(acc), 4),
            "macro_precision": round(float(prec_macro), 4),
            "macro_recall": round(float(rec_macro), 4),
            "macro_f1": round(float(f1_macro), 4),
            "weighted_f1": round(float(f1_weighted), 4),
            "f1_legitimate": round(float(per_class_f1[0]), 4),
            "f1_spam": round(float(per_class_f1[1]), 4),
            "f1_phishing": round(float(per_class_f1[2]), 4),
            "training_time_sec": round(float(train_time), 2),
            "inference_latency_us": round(float(inf_time), 1),
            "model_size_kb": round(float(file_size_kb), 1),
            "confusion_matrix": cm,
        }

    # Save benchmark JSON
    print(f"\n[EXPORT] Saving benchmark results to {OUT_BENCHMARK_JSON}...")
    with open(OUT_BENCHMARK_JSON, "w", encoding="utf-8") as f:
        json.dump(benchmark_results, f, indent=2)

    # Save Markdown Table
    md_table = """# AICS Model Comparison Benchmark Table
| Algorithm | Syllabus Alignment | Accuracy | Macro Precision | Macro Recall | Macro F1 | F1 (Ham) | F1 (Spam) | F1 (Phish) | Latency (us) | Size (KB) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
"""
    for k, v in benchmark_results.items():
        md_table += f"| **{v['name']}** | {v['syllabus_ref'].split(':')[0]} | **{v['accuracy']*100:.2f}%** | {v['macro_precision']:.4f} | {v['macro_recall']:.4f} | **{v['macro_f1']:.4f}** | {v['f1_legitimate']:.4f} | {v['f1_spam']:.4f} | {v['f1_phishing']:.4f} | {v['inference_latency_us']:.1f} us | {v['model_size_kb']:.1f} KB |\n"

    with open(OUT_BENCHMARK_MD, "w", encoding="utf-8") as f:
        f.write(md_table)

    print(f"  Markdown summary saved to {OUT_BENCHMARK_MD}")
    print("\n[OK] PHASE 2 COMPLETE: All 5 AICS Models Trained & Evaluated Successfully!")


if __name__ == "__main__":
    main()
