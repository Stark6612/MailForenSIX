"""
backend/scripts/eval_aics_benchmark.py
──────────────────────────────────────
AICS Phase 3 — Comparative Benchmark Evaluation & Visual Artifacts Generator.
Course: Artificial Intelligence for Cyber Security (23AI2001)

Generates:
  1. backend/proof/aics/aics_confusion_matrices.png (5-panel normalized confusion matrix)
  2. backend/proof/aics/aics_roc_curves.png (Multi-class One-vs-Rest ROC curves with AUCs)
  3. backend/proof/aics/aics_latency_pareto.png (Latency vs. Macro-F1 Pareto frontier)
  4. backend/proof/aics/aics_pr_curves.png (Precision-Recall curves)
  5. backend/proof/aics/aics_model_benchmark.json (Comprehensive empirical metrics)

Usage:
  python eval_aics_benchmark.py
"""

import os
import sys
import time
import json
from pathlib import Path

# Fix matplotlib cache directory before importing
os.environ["MPLCONFIGDIR"] = os.environ.get("TEMP", "C:/temp") + "/mpl_aics"
os.makedirs(os.environ["MPLCONFIGDIR"], exist_ok=True)

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_curve, auc, precision_recall_curve, average_precision_score
)
from sklearn.preprocessing import label_binarize

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR     = Path(__file__).resolve().parent.parent
DATA_PARQUET = BASE_DIR / "data" / "aics_corpus_3class.parquet"
VECTOR_PATH  = BASE_DIR / "models" / "aics" / "aics_tfidf_vectorizer.pkl"
MODELS_AICS  = BASE_DIR / "models" / "aics"
PROOF_AICS   = BASE_DIR / "proof" / "aics"

PROOF_AICS.mkdir(parents=True, exist_ok=True)

OUT_CM_PNG     = PROOF_AICS / "aics_confusion_matrices.png"
OUT_ROC_PNG    = PROOF_AICS / "aics_roc_curves.png"
OUT_PARETO_PNG = PROOF_AICS / "aics_latency_pareto.png"
OUT_PR_PNG     = PROOF_AICS / "aics_pr_curves.png"
OUT_JSON       = PROOF_AICS / "aics_model_benchmark.json"

CLASS_NAMES = ["Legitimate", "Spam", "Phishing"]


def main():
    print("=" * 70)
    print("AICS Phase 3 — Benchmark Visualizations & Diagnostic Curves")
    print("=" * 70)

    # 1. Load Data & Vectorizer
    print("[LOAD] Ingesting test dataset and TF-IDF vectorizer...")
    df = pd.read_parquet(DATA_PARQUET)
    vectorizer = joblib.load(VECTOR_PATH)

    _, X_test_raw, _, y_test = train_test_split(
        df["text"],
        df["label"],
        test_size=0.20,
        random_state=42,
        stratify=df["label"],
    )

    X_test = vectorizer.transform(X_test_raw)
    y_test_bin = label_binarize(y_test, classes=[0, 1, 2])
    n_samples = len(y_test)
    print(f"  Test set: {n_samples:,} samples | Vocabulary: {X_test.shape[1]:,} features")

    # 2. Model Registry
    models_info = [
        ("Multinomial_Naive_Bayes", "Multinomial Naive Bayes", "nb.pkl", "#3b82f6", False),
        ("Support_Vector_Machine",  "Linear SVM (Calibrated)",  "svm.pkl", "#10b981", False),
        ("Logistic_Regression",    "Logistic Regression (L2)", "lr.pkl",  "#8b5cf6", False),
        ("Decision_Tree",          "Decision Tree (CART)",      "dt.pkl",  "#f59e0b", False),
        ("Gradient_Boosted_Trees", "HistGradientBoosting",      "xgb.pkl", "#ef4444", True),
    ]

    results = {}
    preds_dict = {}
    probs_dict = {}

    for key, name, fname, color, is_pipeline in models_info:
        model_path = MODELS_AICS / fname
        if not model_path.exists():
            print(f"[WARN] Model file {fname} not found — skipping.")
            continue

        print(f"\n[EVALUATE] Benchmarking {name}...")
        obj = joblib.load(model_path)

        t0 = time.time()
        if is_pipeline and isinstance(obj, dict) and "selector" in obj:
            X_eval = obj["selector"].transform(X_test).toarray()
            model = obj["model"]
        else:
            X_eval = X_test
            model = obj

        # Predict & Probabilities
        t_inf_start = time.time()
        preds = model.predict(X_eval)
        probs = model.predict_proba(X_eval)
        inf_latency = ((time.time() - t_inf_start) / n_samples) * 1e6  # us

        preds_dict[key] = preds
        probs_dict[key] = probs

        # Metrics
        acc = accuracy_score(y_test, preds)
        macro_prec = precision_score(y_test, preds, average="macro")
        macro_rec  = recall_score(y_test, preds, average="macro")
        macro_f1   = f1_score(y_test, preds, average="macro")
        per_f1     = f1_score(y_test, preds, average=None)
        cm         = confusion_matrix(y_test, preds)

        # Macro ROC-AUC
        roc_auc_scores = []
        for i in range(3):
            fpr, tpr, _ = roc_curve(y_test_bin[:, i], probs[:, i])
            roc_auc_scores.append(auc(fpr, tpr))
        macro_auc = float(np.mean(roc_auc_scores))

        file_size_kb = model_path.stat().st_size / 1024

        print(f"  Accuracy: {acc*100:.2f}% | Macro F1: {macro_f1:.4f} | Macro AUC: {macro_auc:.4f} | Latency: {inf_latency:.1f} us")

        results[key] = {
            "name": name,
            "color": color,
            "accuracy": round(float(acc), 4),
            "macro_precision": round(float(macro_prec), 4),
            "macro_recall": round(float(macro_rec), 4),
            "macro_f1": round(float(macro_f1), 4),
            "macro_auc": round(float(macro_auc), 4),
            "f1_legitimate": round(float(per_f1[0]), 4),
            "f1_spam": round(float(per_f1[1]), 4),
            "f1_phishing": round(float(per_f1[2]), 4),
            "inference_latency_us": round(float(inf_latency), 1),
            "model_size_kb": round(float(file_size_kb), 1),
            "confusion_matrix": cm.tolist(),
        }

    # ══════════════════════════════════════════════════════════════════════════
    # ARTIFACT 1: 5-Panel Normalized Confusion Matrix Figure
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n[PLOT] Rendering 5-Panel Confusion Matrices -> {OUT_CM_PNG.name}...")
    fig, axes = plt.subplots(2, 3, figsize=(16, 10))
    axes = axes.flatten()

    for idx, (key, name, _, _, _) in enumerate(models_info):
        ax = axes[idx]
        cm = np.array(results[key]["confusion_matrix"])
        cm_norm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]

        im = ax.imshow(cm_norm, interpolation='nearest', cmap=plt.cm.Blues, vmin=0, vmax=1.0)
        ax.set_title(f"{name}\nAcc: {results[key]['accuracy']*100:.2f}% | F1: {results[key]['macro_f1']:.4f}",
                     fontsize=11, fontweight='bold', pad=10)

        tick_marks = np.arange(len(CLASS_NAMES))
        ax.set_xticks(tick_marks)
        ax.set_yticks(tick_marks)
        ax.set_xticklabels(CLASS_NAMES, fontsize=9)
        ax.set_yticklabels(CLASS_NAMES, fontsize=9)

        # Annotate cell numbers
        thresh = cm_norm.max() / 2.0
        for i in range(3):
            for j in range(3):
                val_txt = f"{cm_norm[i, j]*100:.1f}%\n({cm[i, j]:,})"
                ax.text(j, i, val_txt,
                        horizontalalignment="center",
                        verticalalignment="center",
                        fontsize=9,
                        color="white" if cm_norm[i, j] > thresh else "black",
                        fontweight='bold' if i == j else 'normal')

        ax.set_ylabel("True Label", fontsize=10, fontweight='semibold')
        ax.set_xlabel("Predicted Label", fontsize=10, fontweight='semibold')
        ax.grid(False)

    # 6th panel: Comparative Model Summary Bar
    ax_sum = axes[5]
    names = [results[k]["name"].replace(" ", "\n") for k, _, _, _, _ in models_info]
    f1s   = [results[k]["macro_f1"] * 100 for k, _, _, _, _ in models_info]
    bar_colors = [c for _, _, _, c, _ in models_info]

    bars = ax_sum.bar(names, f1s, color=bar_colors, width=0.6, edgecolor="#334155", linewidth=1.2)
    ax_sum.set_title("Macro F1-Score Comparison", fontsize=11, fontweight='bold', pad=10)
    ax_sum.set_ylabel("Macro F1 (%)", fontsize=10, fontweight='semibold')
    ax_sum.set_ylim(70, 100)
    ax_sum.grid(axis='y', linestyle='--', alpha=0.5)

    for bar, score in zip(bars, f1s):
        ax_sum.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.8,
                    f"{score:.2f}%", ha='center', va='bottom', fontsize=9, fontweight='bold')

    plt.suptitle("MailForenSIX AICS Multi-Model Normalized Confusion Matrix Suite (Course 23AI2001)",
                 fontsize=14, fontweight='bold', y=0.98)
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    plt.savefig(OUT_CM_PNG, dpi=300)
    plt.close()

    # ══════════════════════════════════════════════════════════════════════════
    # ARTIFACT 2: Multi-Class ROC-AUC Curves (One-vs-Rest)
    # ══════════════════════════════════════════════════════════════════════════
    print(f"[PLOT] Rendering Multi-Class ROC Curves -> {OUT_ROC_PNG.name}...")
    plt.figure(figsize=(9, 7))

    for key, name, _, color, _ in models_info:
        probs = probs_dict[key]
        # Compute macro-average ROC
        all_fpr = np.linspace(0, 1, 100)
        mean_tpr = np.zeros_like(all_fpr)

        for i in range(3):
            fpr, tpr, _ = roc_curve(y_test_bin[:, i], probs[:, i])
            mean_tpr += np.interp(all_fpr, fpr, tpr)

        mean_tpr /= 3.0
        mean_tpr[0] = 0.0
        macro_auc = auc(all_fpr, mean_tpr)

        plt.plot(all_fpr, mean_tpr, color=color, lw=2.2,
                 label=f"{name} (Macro AUC = {macro_auc:.4f})")

    plt.plot([0, 1], [0, 1], color='#94a3b8', lw=1.5, linestyle='--', label='Random Chance (AUC = 0.5000)')
    plt.xlim([-0.01, 1.0])
    plt.ylim([0.0, 1.02])
    plt.xlabel('False Positive Rate (1 - Specificity)', fontsize=11, fontweight='semibold')
    plt.ylabel('True Positive Rate (Sensitivity / Recall)', fontsize=11, fontweight='semibold')
    plt.title('Multi-Class One-vs-Rest ROC Curves Comparison (Course 23AI2001)', fontsize=13, fontweight='bold', pad=12)
    plt.legend(loc="lower right", fontsize=10, frameon=True, framealpha=0.95, facecolor='#ffffff')
    plt.grid(True, linestyle=':', alpha=0.6)
    plt.tight_layout()
    plt.savefig(OUT_ROC_PNG, dpi=300)
    plt.close()

    # ══════════════════════════════════════════════════════════════════════════
    # ARTIFACT 3: Latency vs. Macro-F1 Pareto Frontier Chart
    # ══════════════════════════════════════════════════════════════════════════
    print(f"[PLOT] Rendering Latency vs. F1 Pareto Frontier -> {OUT_PARETO_PNG.name}...")
    plt.figure(figsize=(9.5, 6))

    for key, name, _, color, _ in models_info:
        lat = results[key]["inference_latency_us"]
        f1  = results[key]["macro_f1"] * 100
        size_kb = results[key]["model_size_kb"]

        # Marker size scaled by log(size)
        ms = max(100, min(600, np.log10(size_kb + 10) * 150))
        plt.scatter(lat, f1, color=color, s=ms, alpha=0.85, edgecolors='#0f172a', lw=1.5, zorder=5)

        # Offsets for clean text placement
        offset_y = 0.5 if key != "Logistic_Regression" else -0.7
        offset_x = 1.1 if key == "Gradient_Boosted_Trees" else 1.15
        plt.annotate(
            f"{name}\n({lat:.1f} \u03bcs, {f1:.2f}%)",
            (lat, f1),
            xytext=(lat * offset_x, f1 + offset_y),
            fontsize=9.5,
            fontweight='bold',
            color='#0f172a',
            arrowprops=dict(arrowstyle="->", color='#64748b', lw=1.0)
        )

    # Plot Pareto line between best latency/accuracy tradeoffs
    pareto_pts = sorted([
        (results["Logistic_Regression"]["inference_latency_us"], results["Logistic_Regression"]["macro_f1"] * 100),
        (results["Support_Vector_Machine"]["inference_latency_us"], results["Support_Vector_Machine"]["macro_f1"] * 100),
    ])
    plt.plot([p[0] for p in pareto_pts], [p[1] for p in pareto_pts],
             color='#10b981', linestyle='--', lw=2, label='Optimal Pareto Frontier (Speed vs. Accuracy)')

    plt.xscale('log')
    plt.xlim(0.08, 1000)
    plt.ylim(80, 96)
    plt.xlabel('Inference Latency per Sample (microseconds, Log Scale)', fontsize=11, fontweight='semibold')
    plt.ylabel('Macro F1-Score (%)', fontsize=11, fontweight='semibold')
    plt.title('Operational Trade-off: Inference Latency vs. Macro F1-Score (Pareto Frontier)', fontsize=13, fontweight='bold', pad=12)
    plt.legend(loc='lower right', fontsize=10)
    plt.grid(True, which="both", ls=":", alpha=0.5)

    # Shaded operational zones
    plt.axvspan(0.08, 5, color='#dcfce7', alpha=0.3, label='Real-Time Gateway Triage (<5 \u03bcs)')
    plt.tight_layout()
    plt.savefig(OUT_PARETO_PNG, dpi=300)
    plt.close()

    # ══════════════════════════════════════════════════════════════════════════
    # ARTIFACT 4: Precision-Recall Curves
    # ══════════════════════════════════════════════════════════════════════════
    print(f"[PLOT] Rendering Precision-Recall Curves -> {OUT_PR_PNG.name}...")
    plt.figure(figsize=(9, 7))

    for key, name, _, color, _ in models_info:
        probs = probs_dict[key]
        # Macro AP
        aps = []
        for i in range(3):
            ap = average_precision_score(y_test_bin[:, i], probs[:, i])
            aps.append(ap)
        macro_ap = float(np.mean(aps))

        # Precision-Recall curve on micro-average
        p_micro, r_micro, _ = precision_recall_curve(y_test_bin.ravel(), probs.ravel())
        plt.plot(r_micro, p_micro, color=color, lw=2.2,
                 label=f"{name} (Macro mAP = {macro_ap:.4f})")

    plt.xlim([0.0, 1.02])
    plt.ylim([0.70, 1.02])
    plt.xlabel('Recall (Sensitivity)', fontsize=11, fontweight='semibold')
    plt.ylabel('Precision (Positive Predictive Value)', fontsize=11, fontweight='semibold')
    plt.title('Micro-Averaged Precision-Recall Curves (Course 23AI2001)', fontsize=13, fontweight='bold', pad=12)
    plt.legend(loc="lower left", fontsize=10, frameon=True, framealpha=0.95, facecolor='#ffffff')
    plt.grid(True, linestyle=':', alpha=0.6)
    plt.tight_layout()
    plt.savefig(OUT_PR_PNG, dpi=300)
    plt.close()

    # 3. Export Comprehensive Benchmark JSON
    print(f"\n[EXPORT] Updating benchmark metadata -> {OUT_JSON}...")
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("\n[OK] PHASE 3 COMPLETE: All Benchmark Plots & Visual Artifacts Generated Successfully!")


if __name__ == "__main__":
    main()

