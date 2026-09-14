import joblib, numpy as np, re, time
from pathlib import Path
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
from sklearn.model_selection import train_test_split
import pandas as pd

BASE = Path('.')
DATA = BASE / 'data' / 'training_data.parquet'
vec  = joblib.load(BASE / 'models' / 'tfidf_vectorizer.pkl')
mdl  = joblib.load(BASE / 'models' / 'mailforensix_model.pkl')

URGENCY_KEYWORDS = [
    'urgent','immediately','verify','account suspended','click here',
    'update your','confirm your','limited time','expire','winner',
    'congratulations','free','prize','password','login','bank',
    'wire transfer','invoice','payment required','suspended','blocked',
    'unusual activity','security alert','action required',
]
URG = re.compile('|'.join(re.escape(k) for k in URGENCY_KEYWORDS), re.IGNORECASE)
URL = re.compile(r'https?://\S+|www\.\S+', re.IGNORECASE)

def feat(t):
    return t + ' URLTOKEN'*min(len(URL.findall(t)),10) + ' URGENCYTOKEN'*min(len(URG.findall(t)),5)

df = pd.read_parquet(DATA)
total = len(df)
phish = int(df['label'].sum())
ham   = total - phish
print(f"Dataset    : {total:,} total emails")
print(f"  Phishing : {phish:,} ({phish/total*100:.1f}%)")
print(f"  Ham      : {ham:,} ({ham/total*100:.1f}%)")

X_raw = df['text'].fillna('').astype(str).apply(feat).tolist()
y = df['label'].values
_, X_test_raw, _, y_test = train_test_split(X_raw, y, test_size=0.20, random_state=42, stratify=y)
X_test = vec.transform(X_test_raw)

t0 = time.time()
y_pred = mdl.predict(X_test)
elapsed = time.time() - t0
lat_ms = elapsed * 1000 / len(X_test_raw)

acc  = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred, zero_division=0)
rec  = recall_score(y_test, y_pred, zero_division=0)
f1   = f1_score(y_test, y_pred, zero_division=0)

print(f"\nTest set   : {len(y_test):,} emails (20% stratified hold-out, random_state=42)")
print(f"Accuracy   : {acc:.4f}  ({acc*100:.2f}%)")
print(f"Precision  : {prec:.4f}  ({prec*100:.2f}%)")
print(f"Recall     : {rec:.4f}  ({rec*100:.2f}%)")
print(f"F1 Score   : {f1:.4f}  ({f1*100:.2f}%)")
print(f"Latency    : {lat_ms:.3f} ms/email (classify only)")
print()
print(classification_report(y_test, y_pred, target_names=['ham','phishing']))
