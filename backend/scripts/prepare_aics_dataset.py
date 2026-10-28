"""
scripts/prepare_aics_dataset.py
────────────────────────────────
AICS Phase 1 — Tripartite Email Dataset Preparation & NLP Tokenizer.
Course: Artificial Intelligence for Cyber Security (23AI2001)

Constructs a balanced, deduplicated 3-Class Corpus:
  Class 0: Legitimate (Ham) — Personal and corporate communications
  Class 1: Spam             — Unsolicited bulk commercial/marketing communications
  Class 2: Phishing         — Deceptive credential harvesting, banking lures, and BEC wire fraud

Datasets Consolidated:
  - Enron Corpus (Corporate Ham)
  - SpamAssassin Corpus (Ham + Commercial Spam)
  - LingSpam Corpus (Linguistics Ham + Commercial Spam)
  - CEAS 2008 Corpus (Spam conference benchmark)
  - Nazario Corpus (Classic credential/bank phishing)
  - Nigerian Fraud Corpus (Executive BEC & advance-fee wire fraud)
  - Kaggle Phishing Email Collections

Outputs:
  - backend/data/aics_corpus_3class.parquet
  - backend/models/aics/aics_tfidf_vectorizer.pkl
  - backend/proof/aics/aics_dataset_summary.json

Usage:
  python prepare_aics_dataset.py
"""

import re
import sys
import json
import hashlib
from pathlib import Path
from typing import List, Dict, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).resolve().parent.parent
DATA_DIR    = BASE_DIR / "data"
ARCHIVE_DIR = DATA_DIR / "archive"
MODELS_AICS = BASE_DIR / "models" / "aics"
PROOF_AICS  = BASE_DIR / "proof" / "aics"

MODELS_AICS.mkdir(parents=True, exist_ok=True)
PROOF_AICS.mkdir(parents=True, exist_ok=True)

OUT_PARQUET = DATA_DIR / "aics_corpus_3class.parquet"
OUT_VECTOR  = MODELS_AICS / "aics_tfidf_vectorizer.pkl"
OUT_SUMMARY = PROOF_AICS / "aics_dataset_summary.json"

# ── Domain-Specific Synthetic Tokenization Patterns ────────────────────────────
_HTML_TAG_RE   = re.compile(r"<[^>]+>", re.IGNORECASE)
_URL_RE        = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)
_IP_RE         = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_CURRENCY_RE   = re.compile(r"[\$€£₹]\s*\d+(?:[.,]\d+)?|\b(?:usd|eur|inr|gbp|dollars?)\s*\d+\b", re.IGNORECASE)

URGENCY_KEYWORDS = [
    r"\burgent\b", r"\bimmediately\b", r"\bverify your\b", r"\baccount suspended\b",
    r"\baction required\b", r"\bsecurity alert\b", r"\bunauthorized access\b",
    r"\bconfirm your identity\b", r"\bclick here\b", r"\breset your password\b",
    r"\blimited time\b", r"\bwire transfer\b", r"\bpayment overdue\b",
    r"\bupdate payment\b", r"\bbank account\b", r"\blogin immediately\b",
]
_URGENCY_RE = re.compile("|".join(URGENCY_KEYWORDS), re.IGNORECASE)


def preprocess_text(text: str) -> str:
    """Cleans raw email text and injects domain-specific synthetic tokens."""
    if not isinstance(text, str) or not text.strip():
        return ""

    # 1. Strip HTML tags
    clean = _HTML_TAG_RE.sub(" ", text)

    # 2. Inject synthetic cyber tokens
    clean = _URL_RE.sub(" URL_TOKEN ", clean)
    clean = _IP_RE.sub(" IP_TOKEN ", clean)
    clean = _CURRENCY_RE.sub(" CURRENCY_TOKEN ", clean)
    clean = _URGENCY_RE.sub(" URGENCY_TOKEN ", clean)

    # 3. Normalize whitespace and lowercase
    clean = re.sub(r"\s+", " ", clean).strip().lower()
    return clean


def load_dataset_slice(path: Path, text_cols: List[str], label_col: str, 
                       class_mapping: Dict[any, int], max_samples: int = None) -> List[Dict]:
    """Helper to safely ingest and standardize a CSV dataset."""
    if not path.exists():
        print(f"  [WARN] Dataset not found: {path.name} — skipping.")
        return []

    print(f"  [INGEST] Loading {path.name}...")
    try:
        df = pd.read_csv(path, low_memory=False, on_bad_lines='skip')
    except Exception as e:
        print(f"  [ERROR] Failed to read {path.name}: {e}")
        return []

    # Find matching text column(s)
    available_cols = set(df.columns)
    matched_text_cols = [c for c in text_cols if c in available_cols]
    if not matched_text_cols:
        print(f"  [WARN] No text column found in {path.name} (checked {text_cols})")
        return []

    if label_col not in available_cols:
        print(f"  [WARN] Label column '{label_col}' not found in {path.name}")
        return []

    records = []
    for _, row in df.iterrows():
        raw_label = row[label_col]
        if raw_label not in class_mapping:
            continue

        target_class = class_mapping[raw_label]
        # Combine subject + body if available
        combined_text = " ".join(str(row[c]) for c in matched_text_cols if pd.notna(row[c]))
        cleaned = preprocess_text(combined_text)

        if len(cleaned) >= 20:  # Minimum meaningful length
            records.append({
                "text": cleaned,
                "label": target_class,
                "source": path.name,
            })

    if max_samples and len(records) > max_samples:
        import random
        random.seed(42)
        records = random.sample(records, max_samples)

    print(f"    -> Extracted {len(records):,} valid records from {path.name}")
    return records


def main():
    print("=" * 70)
    print("AICS Phase 1 — Building 3-Class Email Threat Corpus")
    print("Classes: 0 = Legitimate (Ham), 1 = Spam, 2 = Phishing/BEC")
    print("=" * 70)

    corpus_records = []

    # 1. Enron Corporate Corpus — Pure Legitimate (Ham = 0)
    corpus_records.extend(load_dataset_slice(
        path=ARCHIVE_DIR / "Enron.csv",
        text_cols=["subject", "body"],
        label_col="label",
        class_mapping={0: 0, "0": 0},
        max_samples=16_000,
    ))

    # 2. SpamAssassin — Ham (0) and Commercial Spam (1)
    corpus_records.extend(load_dataset_slice(
        path=ARCHIVE_DIR / "SpamAssasin.csv",
        text_cols=["subject", "body"],
        label_col="label",
        class_mapping={0: 0, "0": 0, 1: 1, "1": 1},
    ))

    # 3. LingSpam — Academic Ham (0) and Bulk Commercial Spam (1)
    corpus_records.extend(load_dataset_slice(
        path=ARCHIVE_DIR / "Ling.csv",
        text_cols=["subject", "body"],
        label_col="label",
        class_mapping={0: 0, "0": 0, 1: 1, "1": 1},
    ))

    # 4. CEAS 2008 Benchmark — Unsolicited Bulk Spam (1) and Legitimate (0)
    corpus_records.extend(load_dataset_slice(
        path=ARCHIVE_DIR / "CEAS_08.csv",
        text_cols=["subject", "body"],
        label_col="label",
        class_mapping={1: 1, "1": 1, 0: 0, "0": 0},
        max_samples=18_000,
    ))

    # 5. Nazario Phishing Corpus — Explicit Phishing Lures (2)
    corpus_records.extend(load_dataset_slice(
        path=ARCHIVE_DIR / "Nazario.csv",
        text_cols=["subject", "body"],
        label_col="label",
        class_mapping={1: 2, "1": 2, "phishing": 2},
    ))

    # 6. Nigerian Fraud Corpus — BEC Wire Fraud & Impersonation (2)
    corpus_records.extend(load_dataset_slice(
        path=ARCHIVE_DIR / "Nigerian_Fraud.csv",
        text_cols=["subject", "body"],
        label_col="label",
        class_mapping={1: 2, "1": 2, "phishing": 2},
    ))

    # 7. Kaggle Phishing Email Collections — Safe (0) and Phishing (2)
    corpus_records.extend(load_dataset_slice(
        path=DATA_DIR / "Phishing_Email.csv",
        text_cols=["Email Text"],
        label_col="Email Type",
        class_mapping={"Safe Email": 0, "Phishing Email": 2},
    ))

    corpus_records.extend(load_dataset_slice(
        path=ARCHIVE_DIR / "phishing_email.csv",
        text_cols=["text_combined"],
        label_col="label",
        class_mapping={1: 2, "1": 2},
        max_samples=12_000,
    ))

    print(f"\n[DEDUPLICATION] Raw collected records: {len(corpus_records):,}")
    df_raw = pd.DataFrame(corpus_records)

    # Deduplicate based on MD5 checksum of preprocessed text
    df_raw["text_hash"] = df_raw["text"].apply(lambda t: hashlib.md5(t.encode("utf-8")).hexdigest())
    df_clean = df_raw.drop_duplicates(subset=["text_hash"]).drop(columns=["text_hash"]).reset_index(drop=True)

    print(f"[DEDUPLICATION] Clean unique records: {len(df_clean):,}")
    print("\n[DISTRIBUTION] Raw distribution before balancing:")
    print(df_clean["label"].value_counts().rename({0: "Legitimate (0)", 1: "Spam (1)", 2: "Phishing (2)"}))

    # Balance classes so each class has approximately ~15,000–18,000 samples
    min_count = min(df_clean["label"].value_counts())
    target_per_class = min(min_count, 18_000)
    print(f"\n[BALANCING] Sampling {target_per_class:,} instances per class for optimal class balance...")

    balanced_dfs = []
    for cls in [0, 1, 2]:
        sub_df = df_clean[df_clean["label"] == cls]
        if len(sub_df) > target_per_class:
            sub_df = sub_df.sample(n=target_per_class, random_state=42)
        balanced_dfs.append(sub_df)

    df_final = pd.concat(balanced_dfs).sample(frac=1.0, random_state=42).reset_index(drop=True)

    label_names = {0: "Legitimate", 1: "Spam", 2: "Phishing"}
    df_final["label_name"] = df_final["label"].map(label_names)

    print("\n[FINAL CORPUS DISTRIBUTION]:")
    for cls_id, name in label_names.items():
        cnt = (df_final["label"] == cls_id).sum()
        pct = (cnt / len(df_final)) * 100
        print(f"  Class {cls_id} ({name:<10}): {cnt:,} samples ({pct:.1f}%)")
    print(f"  Total Cleaned Corpus  : {len(df_final):,} emails")

    # Save to Parquet
    print(f"\n[EXPORT] Saving corpus to {OUT_PARQUET}...")
    df_final.to_parquet(OUT_PARQUET, index=False)

    # ── Phase 1.2: Train & Persist Standardized TF-IDF Vectorizer ───────────────
    print("\n" + "=" * 70)
    print("AICS Phase 1.2 — Fitting Standardized Multi-Class TF-IDF Vectorizer")
    print("=" * 70)

    X_train, X_test, y_train, y_test = train_test_split(
        df_final["text"],
        df_final["label"],
        test_size=0.20,
        random_state=42,
        stratify=df_final["label"],
    )

    print(f"  Train split: {len(X_train):,} samples (80%)")
    print(f"  Test split : {len(X_test):,} samples (20%)")

    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=10_000,
        sublinear_tf=True,
        stop_words="english",
        min_df=3,
        max_df=0.90,
    )

    print("  Fitting vectorizer on train split...")
    vectorizer.fit(X_train)
    vocab_size = len(vectorizer.vocabulary_)
    print(f"  Vocabulary size: {vocab_size:,} features")

    # Verify synthetic tokens in vocabulary
    tokens_found = [tok for tok in ["url_token", "ip_token", "urgency_token", "currency_token"] 
                    if tok in vectorizer.vocabulary_]
    print(f"  Verified synthetic cyber tokens in vocabulary: {tokens_found}")

    print(f"  Saving vectorizer artifact to {OUT_VECTOR}...")
    joblib.dump(vectorizer, OUT_VECTOR)

    # Save summary metadata
    summary = {
        "dataset_name": "MailForenSIX AICS 3-Class Benchmark Corpus",
        "total_samples": len(df_final),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "classes": {
            "0": {"name": "Legitimate", "samples": int((df_final['label'] == 0).sum())},
            "1": {"name": "Spam",       "samples": int((df_final['label'] == 1).sum())},
            "2": {"name": "Phishing",   "samples": int((df_final['label'] == 2).sum())},
        },
        "vectorizer": {
            "max_features": 10000,
            "ngram_range": [1, 2],
            "sublinear_tf": True,
            "vocab_size": vocab_size,
            "synthetic_tokens": tokens_found,
        },
        "sources": list(df_final["source"].unique()),
    }

    with open(OUT_SUMMARY, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"  Summary saved to {OUT_SUMMARY}")
    print("\n[OK] PHASE 1 COMPLETE: 3-Class Corpus & TF-IDF Vectorizer Successfully Built!")


if __name__ == "__main__":
    main()
