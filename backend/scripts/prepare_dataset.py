"""
scripts/prepare_dataset.py
──────────────────────────
Merges all CSV datasets into a single deduplicated training_data.parquet.

Datasets handled:
  archive/phishing_email.csv  — Kaggle phishing collection
  archive/Nazario.csv         — Nazario phishing corpus
  archive/CEAS_08.csv         — CEAS 2008 spam corpus
  archive/SpamAssasin.csv     — SpamAssassin corpus
  archive/Nigerian_Fraud.csv  — Nigerian fraud emails
  archive/Ling.csv            — Ling-spam corpus
  archive/Enron.csv           — Enron (ham source, sample 20k)

Output: backend/data/training_data.parquet
        Columns: text (str), label (int)  [0=ham, 1=phishing/spam]

Usage:
    python scripts/prepare_dataset.py
"""

import hashlib
import sys
from pathlib import Path

import pandas as pd

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).resolve().parent.parent
DATA_DIR    = BASE_DIR / "data" / "archive"
DATA_ROOT   = BASE_DIR / "data"          # for datasets at data/ root (not archive/)
OUT_PATH    = BASE_DIR / "data" / "training_data.parquet"
PROOF_DIR   = BASE_DIR / "proof"
PROOF_DIR.mkdir(exist_ok=True)

# ── Per-dataset schema config ──────────────────────────────────────────────────
# (filename, text_col_candidates, label_col_candidates, label_positive_values, sample_n)
# label_positive_values: values in the label column that mean phishing/spam (-> 1)
# archive/ datasets (existing)
ARCHIVE_DATASETS = [
    {
        "file":   "phishing_email.csv",
        "text":   ["text_combined", "Email Text", "text", "body", "email_text", "message"],
        "label":  ["Email Type", "label", "spam", "is_phishing", "class"],
        "pos":    ["Phishing Email", "1", 1, "spam", "phishing"],
        "sample": 30_000,
        "dir":    "archive",
    },
    {
        "file":   "Nazario.csv",
        "text":   ["body", "text", "email_text", "content", "Email Text", "message"],
        "label":  ["label", "class", "spam", "is_phishing", "Email Type"],
        "pos":    [1, "1", "spam", "phishing", "Phishing Email"],
        "sample": None,
        "dir":    "archive",
    },
    {
        "file":   "CEAS_08.csv",
        "text":   ["body", "text", "email_text", "content", "Email Text", "message"],
        "label":  ["label", "spam", "class", "is_phishing"],
        "pos":    [1, "1", "spam"],
        "sample": 20_000,
        "dir":    "archive",
    },
    {
        "file":   "SpamAssasin.csv",
        "text":   ["text", "body", "email_text", "content", "Email Text", "message"],
        "label":  ["label", "spam", "class", "is_phishing"],
        "pos":    [1, "1", "spam"],
        "sample": None,
        "dir":    "archive",
    },
    {
        "file":   "Nigerian_Fraud.csv",
        "text":   ["body", "text", "email_text", "content", "Email Text", "message"],
        "label":  ["label", "spam", "class", "is_phishing"],
        "pos":    [1, "1", "spam", "phishing", "Phishing Email"],
        "sample": None,
        "dir":    "archive",
    },
    {
        "file":   "Ling.csv",
        "text":   ["text", "body", "email_text", "content", "Email Text", "message"],
        "label":  ["label", "spam", "class", "is_phishing"],
        "pos":    [1, "1", "spam"],
        "sample": None,
        "dir":    "archive",
    },
    {
        "file":   "Enron.csv",
        "text":   ["body", "text", "email_text", "content", "Email Text", "message"],
        "label":  ["label", "spam", "class", "is_phishing"],
        "pos":    [1, "1", "spam"],
        "sample": 20_000,
        "dir":    "archive",
    },
    # ── New: Kaggle Phishing Email Dataset (Phishing_Email.csv at data/ root) ────
    {
        "file":   "Phishing_Email.csv",
        "text":   ["Email Text"],
        "label":  ["Email Type"],
        "pos":    ["Phishing Email"],
        "sample": 15_000,   # ~15k phishing + ham from this dataset
        "dir":    "root",   # data/ root, not archive/
    },
    # ── New: Adversarial BEC Email Dataset (synthetic_emails.csv) ────────────────
    {
        "file":   "synthetic_emails.csv",
        "text":   ["body", "subject"],
        "label":  ["label"],
        "pos":    [1, "1"],
        "sample": None,
        "dir":    "root",
    },
    # ── New: Adversarial BEC (poisoned / obfuscated variant) ─────────────────────
    {
        "file":   "synthetic_emails_poisoned.csv",
        "text":   ["body", "subject"],
        "label":  ["label"],
        "pos":    [1, "1"],
        "sample": None,
        "dir":    "root",
    },
]
DATASETS = ARCHIVE_DATASETS


def _find_col(df: pd.DataFrame, candidates: list) -> str | None:
    """Return the first candidate column name that exists in df (case-insensitive)."""
    cols_lower = {c.lower(): c for c in df.columns}
    for cand in candidates:
        if cand.lower() in cols_lower:
            return cols_lower[cand.lower()]
    return None


def _md5(text: str) -> str:
    return hashlib.md5(text.encode("utf-8", errors="replace")).hexdigest()


def _normalize_label_val(v) -> str:
    """Normalize label values: 1.0 -> '1', '1' -> '1', 'spam' -> 'spam'."""
    try:
        return str(int(float(str(v))))
    except (ValueError, TypeError):
        return str(v).strip()


def load_dataset(cfg: dict) -> pd.DataFrame | None:
    if cfg.get("dir") == "root":
        path = DATA_ROOT / cfg["file"]
    else:
        path = DATA_DIR / cfg["file"]
    if not path.exists():
        print(f"  [SKIP] {cfg['file']} — not found at {path}")
        return None

    print(f"  [LOAD] {cfg['file']} ({path.stat().st_size // 1_048_576} MB)…")

    try:
        # Try utf-8 first, fall back to latin-1
        try:
            df = pd.read_csv(path, low_memory=False)
        except UnicodeDecodeError:
            df = pd.read_csv(path, encoding="latin-1", low_memory=False)
    except Exception as e:
        print(f"  [ERR]  {cfg['file']} — {e}")
        return None

    print(f"         Columns: {list(df.columns)}")

    text_col  = _find_col(df, cfg["text"])
    label_col = _find_col(df, cfg["label"])

    if text_col is None:
        print(f"  [ERR]  No text column found among {cfg['text']}")
        return None
    if label_col is None:
        print(f"  [WARN] No label column found — treating all as phishing (fraud datasets)")
        df["_label"] = 1
        label_col = "_label"

    # Normalise label -> 0/1 (handles int, float, and string label values)
    pos_vals = set()
    for v in cfg["pos"]:
        pos_vals.add(str(v).strip())
        pos_vals.add(_normalize_label_val(v))
    df["label"] = df[label_col].apply(lambda v: 1 if _normalize_label_val(v) in pos_vals or str(v).strip() in pos_vals else 0)
    df["text"]  = df[text_col].fillna("").astype(str)

    # Drop empty text
    df = df[df["text"].str.strip().str.len() > 10].copy()

    # Sample if requested
    if cfg["sample"] and len(df) > cfg["sample"]:
        df = df.sample(cfg["sample"], random_state=42)

    result = df[["text", "label"]].reset_index(drop=True)
    n_pos = result["label"].sum()
    print(f"         Loaded {len(result):,} rows | spam/phishing: {n_pos:,} | ham: {len(result)-n_pos:,}")
    return result


def main():
    import json
    print("\n=== MailForenSIX — Dataset Preparation ===\n")
    frames = []
    proof_datasets = []

    for cfg in DATASETS:
        df = load_dataset(cfg)
        if df is not None and len(df) > 0:
            frames.append(df)
            proof_datasets.append({
                "file": cfg["file"],
                "rows": len(df),
                "phishing": int(df["label"].sum()),
                "ham": int((df["label"] == 0).sum()),
            })

    if not frames:
        print("[ERROR] No datasets loaded — aborting.")
        sys.exit(1)

    print("\n[MERGE] Concatenating datasets…")
    merged = pd.concat(frames, ignore_index=True)
    print(f"        Total rows before dedup: {len(merged):,}")

    # Deduplicate by MD5 of body text
    print("[DEDUP] Computing MD5 hashes…")
    merged["_md5"] = merged["text"].apply(_md5)
    before = len(merged)
    merged = merged.drop_duplicates(subset="_md5").drop(columns="_md5")
    removed = before - len(merged)
    print(f"        Removed {removed:,} duplicates -> {len(merged):,} unique rows")

    # Class balance report
    n_pos = merged["label"].sum()
    n_neg = len(merged) - n_pos
    ratio = n_pos / len(merged) * 100
    print(f"\n[BALANCE] Phishing/Spam: {n_pos:,} ({ratio:.1f}%) | Ham: {n_neg:,} ({100-ratio:.1f}%)")

    # Save parquet
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    merged.to_parquet(OUT_PATH, index=False)
    size_mb = OUT_PATH.stat().st_size / 1_048_576
    print(f"\n[SAVED]  {OUT_PATH}  ({size_mb:.1f} MB)")
    print(f"         Rows: {len(merged):,}  |  Columns: {list(merged.columns)}")

    # Write proof artifact
    proof = {
        "datasets": proof_datasets,
        "total_rows_before_dedup": before,
        "duplicates_removed": removed,
        "total_rows": len(merged),
        "phishing_rows": int(n_pos),
        "ham_rows": int(n_neg),
        "phishing_pct": round(ratio, 2),
    }
    proof_path = PROOF_DIR / "dataset_prep.json"
    with open(proof_path, "w") as f:
        json.dump(proof, f, indent=2)
    print(f"[PROOF]  {proof_path}")
    print("\n=== Done ===\n")


if __name__ == "__main__":
    main()
