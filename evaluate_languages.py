"""
evaluate_languages.py - honest multilingual benchmark.

Runs the saved English-trained Random Forest on data/multilingual_sample.csv
(hand-written French + Arabic emails) and reports per-language accuracy,
false-positive rate on legit mail, recall on phishing mail, and how many
emails were destroyed by the English-only cleaning step ([^a-z] filter).

Saves everything to results/multilingual_metrics.json.

FACTUAL NOTE (do not edit away): the training pipeline and TF-IDF model are
English-only. French text is degraded (accents stripped) but readable;
Arabic script is removed entirely by cleaning, so Arabic predictions below
are made on empty text and are not meaningful detections.
"""
import json
import os
import sys

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score

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

import core  # noqa: E402  (local module, needs BASE-adjacent import path)

core.load_artifacts()
MODEL = core.MODEL
VECTORIZER = core.VECTORIZER

df = pd.read_csv(os.path.join(BASE, "data", "multilingual_sample.csv"))
df["label"] = df["label"].map({"phishing": 1, "legit": 0})
df["clean"] = df["text"].apply(core.clean_email_text)
df["destroyed_by_cleaning"] = df["clean"].str.len() == 0

X = VECTORIZER.transform(df["clean"])
df["pred"] = MODEL.predict(X)
probas = MODEL.predict_proba(X)
df["conf"] = [float(p[df["pred"].iloc[i]]) for i, p in enumerate(probas)]

out = {"dataset": "data/multilingual_sample.csv (hand-written FR/AR sample)",
       "model": "English-only Random Forest + TF-IDF (trained on cleaned_emails.csv)",
       "languages": {}}

print("per-language results (english-trained model)")
print("=" * 55)
for lang, group in df.groupby("language"):
    y = group["label"].values
    p = group["pred"].values
    legit = group[group["label"] == 0]
    phish = group[group["label"] == 1]
    stats = {
        "n": int(len(group)),
        "accuracy": float(accuracy_score(y, p)),
        "destroyed_by_cleaning": int(group["destroyed_by_cleaning"].sum()),
        "legit_n": int(len(legit)),
        "legit_false_positives": int((legit["pred"] == 1).sum()),
        "legit_fpr": float((legit["pred"] == 1).mean()) if len(legit) else 0.0,
        "phish_n": int(len(phish)),
        "phish_caught": int((phish["pred"] == 1).sum()),
        "phish_recall": float((phish["pred"] == 1).mean()) if len(phish) else 0.0,
    }
    out["languages"][lang] = stats
    print(f"\nlanguage: {lang}  ({stats['n']} emails)")
    print(f"  accuracy:                 {stats['accuracy']:.1%}")
    print(f"  destroyed by cleaning:    {stats['destroyed_by_cleaning']}/{stats['n']}")
    print(f"  legit FP rate:            {stats['legit_fpr']:.1%} "
          f"({stats['legit_false_positives']}/{stats['legit_n']})")
    print(f"  phish recall:             {stats['phish_recall']:.1%} "
          f"({stats['phish_caught']}/{stats['phish_n']})")

print("\nper-email detail:")
print("-" * 55)
for _, row in df.iterrows():
    guess = "PHISHING" if row["pred"] == 1 else "LEGIT"
    ok = "OK " if row["pred"] == row["label"] else "WRONG"
    expected = "PHISHING" if row["label"] == 1 else "LEGIT"
    print(f"[{ok}] {row['language']} | expected={expected:9s}"
          f" got={guess:9s} conf={row['conf']:.0%} | {row['text'][:50]}...")

print("\nwhat this shows:")
print("  - french keeps enough latin alphabet to partially survive cleaning,")
print("    but every legit french email here is still flagged (model never saw french).")
print("  - arabic text is reduced to nothing by the [^a-z] filter, so arabic")
print("    predictions are made on empty text -> the model is english-only.")

with open(os.path.join(RESULTS, "multilingual_metrics.json"), "w", encoding="utf-8") as fh:
    json.dump(_round_floats(out), fh, indent=2, ensure_ascii=False)
print("saved: results/multilingual_metrics.json")
