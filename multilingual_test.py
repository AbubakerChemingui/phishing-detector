# multilingual robustness test
# runs the english-trained model on a small hand-written fr/ar sample set
# to demonstrate the language coverage gap documented in the report

import os
import sys
import re
import joblib
import pandas as pd
from sklearn.metrics import accuracy_score

# windows console defaults to cp1252 which can't print arabic
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

base = os.path.dirname(__file__)
model = joblib.load(os.path.join(base, "random_forest_model.pkl"))
vectorizer = joblib.load(os.path.join(base, "random_forest_vectorizer.pkl"))


def clean_email_text(raw_text):
    raw_text = str(raw_text).lower()
    raw_text = re.sub(r'http\S+|www\S+', ' url ', raw_text)
    raw_text = re.sub(r'[^a-z\s]', ' ', raw_text)
    raw_text = re.sub(r'\s+', ' ', raw_text).strip()
    return raw_text


df = pd.read_csv(os.path.join(base, "data", "multilingual_sample.csv"))
df["label"] = df["label"].map({"phishing": 1, "legit": 0})

df["clean"] = df["text"].apply(clean_email_text)
# an empty cleaned string means the pipeline destroyed every character of the email
df["destroyed_by_cleaning"] = df["clean"].str.len() == 0

X = vectorizer.transform(df["clean"])
df["pred"] = model.predict(X)
df["conf"] = [p[df["pred"].iloc[i]] for i, p in enumerate(model.predict_proba(X))]

print("per-language results (english-trained model)")
print("=" * 55)
for lang, group in df.groupby("language"):
    acc = accuracy_score(group["label"], group["pred"])
    destroyed = group["destroyed_by_cleaning"].sum()
    print(f"\nlanguage: {lang}  ({len(group)} emails)")
    print(f"  accuracy:                 {acc:.1%}")
    print(f"  emails fully destroyed by cleaning: {destroyed}/{len(group)}")

print("\nper-email detail:")
print("-" * 55)
for _, row in df.iterrows():
    guess = "PHISHING" if row["pred"] == 1 else "LEGIT"
    ok = "OK " if row["pred"] == row["label"] else "WRONG"
    expected = "PHISHING" if row["label"] == 1 else "LEGIT"
    print(f"[{ok}] {row['language']} | expected={expected:9s}"
          f" got={guess:9s} conf={row['conf']:.0%} | {row['text'][:50]}...")

print("\nwhat this shows:")
print("  - french keeps enough latin alphabet to partially survive cleaning")
print("  - arabic text is reduced to nothing by the [^a-z] filter, so predictions")
print("    there are basically random -> the model is english-only as documented")
