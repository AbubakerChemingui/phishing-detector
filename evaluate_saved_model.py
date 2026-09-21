"""
evaluate_saved_model.py - honest baseline of the SAVED Random Forest on its training corpus.

Rebuilds the EXACT 80/20 split from data/cleaned_emails.csv (same file, same seed,
same stratify as train_random_forest.py), evaluates the saved model + vectorizer,
prints metrics and saves them to results/baseline_metrics.json.
Then evaluates the same saved model on the cross-dataset holdout
data/validation/Phishing_Email.csv -> results/cross_dataset_metrics.json.

IMPORTANT: labels in cleaned_emails.csv are ALREADY 0/1. Do NOT remap them
(e.g. 'phishing'->1); a remap like that silently turns every label into 0.
"""
import json
import os
import re
import sys

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(BASE, "results")
os.makedirs(RESULTS, exist_ok=True)


def _round_floats(o):
    # Multithreaded BLAS can flip the last float bit between runs;
    # 6 decimals keeps files byte-stable without losing any real precision.
    if isinstance(o, float):
        return round(o, 6)
    if isinstance(o, dict):
        return {k: _round_floats(v) for k, v in o.items()}
    if isinstance(o, list):
        return [_round_floats(v) for v in o]
    return o

model = joblib.load(os.path.join(BASE, "random_forest_model.pkl"))
vectorizer = joblib.load(os.path.join(BASE, "random_forest_vectorizer.pkl"))

# ---------------------------------------------------------------- 1. in-corpus baseline
df = pd.read_csv(os.path.join(BASE, "data", "cleaned_emails.csv"))
df = df.dropna(subset=["clean_text"])
X = df["clean_text"]
y = df["label"].astype(int).values  # already 0/1 in this file
print("label distribution in corpus:", pd.Series(y).value_counts().to_dict())

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"train={len(X_train)} test={len(X_test)} "
      f"test_positives={int(y_test.sum())} test_negatives={int((y_test == 0).sum())}")

Xt = vectorizer.transform(X_test)
yp = model.predict(Xt)
ypr = model.predict_proba(Xt)[:, 1]
tn, fp, fn, tp = confusion_matrix(y_test, yp).ravel()

metrics = {
    "dataset": "data/cleaned_emails.csv (same 80/20 split, seed 42, stratify as training)",
    "n_test": int(len(y_test)),
    "accuracy": float(accuracy_score(y_test, yp)),
    "precision": float(precision_score(y_test, yp, zero_division=0)),
    "recall": float(recall_score(y_test, yp, zero_division=0)),
    "f1": float(f1_score(y_test, yp, zero_division=0)),
    "roc_auc": float(roc_auc_score(y_test, ypr)),
    "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    "fpr": float(fp / (fp + tn)),
}
metrics = _round_floats(metrics)
print(json.dumps(metrics, indent=2))
with open(os.path.join(RESULTS, "baseline_metrics.json"), "w", encoding="utf-8") as fh:
    json.dump(metrics, fh, indent=2)

# ------------------------------------------------------- 2. cross-dataset holdout
def clean_email_text(raw_text):
    raw_text = str(raw_text).lower()
    raw_text = re.sub(r'http\S+|www\S+', ' url ', raw_text)
    raw_text = re.sub(r'[^a-z\s]', ' ', raw_text)
    raw_text = re.sub(r'\s+', ' ', raw_text).strip()
    return raw_text


nd = pd.read_csv(os.path.join(BASE, "data", "validation", "Phishing_Email.csv"))
text_col = "Email Text" if "Email Text" in nd.columns else nd.columns[1]
label_col = "Email Type" if "Email Type" in nd.columns else nd.columns[2]
nd = nd.dropna(subset=[text_col, label_col])
nd["label"] = nd[label_col].apply(lambda x: 1 if "phish" in str(x).lower() else 0)
nd["cleaned"] = nd[text_col].apply(clean_email_text)
nd = nd[nd["cleaned"].str.len() > 0]

X2 = vectorizer.transform(nd["cleaned"])
y2 = nd["label"].values
yp2 = model.predict(X2)
ypr2 = model.predict_proba(X2)[:, 1]
tn2, fp2, fn2, tp2 = confusion_matrix(y2, yp2).ravel()

metrics2 = {
    "dataset": "data/validation/Phishing_Email.csv (unseen corpus)",
    "n_test": int(len(y2)),
    "accuracy": float(accuracy_score(y2, yp2)),
    "precision": float(precision_score(y2, yp2, zero_division=0)),
    "recall": float(recall_score(y2, yp2, zero_division=0)),
    "f1": float(f1_score(y2, yp2, zero_division=0)),
    "roc_auc": float(roc_auc_score(y2, ypr2)),
    "confusion": {"tn": int(tn2), "fp": int(fp2), "fn": int(fn2), "tp": int(tp2)},
    "fpr": float(fp2 / (fp2 + tn2)),
}
metrics2 = _round_floats(metrics2)
print(json.dumps(metrics2, indent=2))
with open(os.path.join(RESULTS, "cross_dataset_metrics.json"), "w", encoding="utf-8") as fh:
    json.dump(metrics2, fh, indent=2)

print("saved: results/baseline_metrics.json, results/cross_dataset_metrics.json")
