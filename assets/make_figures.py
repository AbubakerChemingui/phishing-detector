"""
make_figures.py - generate defense-ready figures from committed results.
Reads results/*.json (no retraining) + rebuilds the exact split once for
the ROC curve. Outputs PNGs into assets/figures/.
"""
import json
import os
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import auc, confusion_matrix, roc_curve
from sklearn.model_selection import train_test_split

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIG = os.path.join(BASE, "assets", "figures")
os.makedirs(FIG, exist_ok=True)
plt.rcParams.update({"font.size": 10, "figure.dpi": 150})


def heatmap(cm, labels, title, path):
    fig, ax = plt.subplots(figsize=(4.6, 4.0))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks([0, 1], labels=["Legit (pred)", "Phish (pred)"])
    ax.set_yticks([0, 1], labels=["Legit (true)", "Phish (true)"])
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center",
                    fontsize=13, fontweight="bold",
                    color="white" if cm[i, j] > cm.max() / 2 else "black")
    acc = (cm[0, 0] + cm[1, 1]) / cm.sum()
    ax.set_title(f"{title}\naccuracy={acc:.2%}")
    fig.colorbar(im, ax=ax, shrink=0.8)
    fig.tight_layout()
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    print("saved", path)


base = json.load(open(os.path.join(BASE, "results", "baseline_metrics.json")))
cross = json.load(open(os.path.join(BASE, "results", "cross_dataset_metrics.json")))
c = base["confusion"]
heatmap(np.array([[c["tn"], c["fp"]], [c["fn"], c["tp"]]]),
        None, "Random Forest — holdout (n=16,438)",
        os.path.join(FIG, "confusion_holdout.png"))
c = cross["confusion"]
heatmap(np.array([[c["tn"], c["fp"]], [c["fn"], c["tp"]]]),
        None, "Random Forest — unseen corpus (n=18,630)",
        os.path.join(FIG, "confusion_cross.png"))

# ROC + operating points (rebuild exact split, saved model, no retraining)
model = joblib.load(os.path.join(BASE, "random_forest_model.pkl"))
vectorizer = joblib.load(os.path.join(BASE, "random_forest_vectorizer.pkl"))
df = pd.read_csv(os.path.join(BASE, "data", "cleaned_emails.csv"))
df = df.dropna(subset=["clean_text"])
X = df["clean_text"]
y = df["label"].astype(int).values
_, Xt_, _, yt_ = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
proba = model.predict_proba(vectorizer.transform(Xt_))[:, 1]
fpr, tpr, _ = roc_curve(yt_, proba)
fig, ax = plt.subplots(figsize=(5.0, 4.4))
ax.plot(fpr, tpr, label=f"RF (AUC={auc(fpr, tpr):.4f})", linewidth=2)
ax.plot([0, 1], [0, 1], "--", color="gray", label="chance")
for t in (0.50, 0.65, 0.85):
    yp = (proba >= t).astype(int)
    tn, fp, fn, tp = confusion_matrix(yt_, yp).ravel()
    ax.plot(fp / (fp + tn), tp / (tp + fn), "o", markersize=7, label=f"thr={t}")
ax.set_xlabel("False positive rate")
ax.set_ylabel("Recall")
ax.set_title("ROC — Random Forest holdout")
ax.legend(loc="lower right", fontsize=8)
fig.tight_layout()
fig.savefig(os.path.join(FIG, "roc_holdout.png"), bbox_inches="tight")
plt.close(fig)
print("saved", os.path.join(FIG, "roc_holdout.png"))

# URL risk bars (measured values)
items = [("clean URL", 0.00), ("@ userinfo", 0.05), ("shortener", 0.15),
         ("plain IP", 0.30), ("hex IP", 0.30), ("decimal IP", 0.30),
         ("percent-encoded IP", 0.45)]
names = [n for n, _ in items][::-1]
vals = [v for _, v in items][::-1]
fig, ax = plt.subplots(figsize=(5.4, 3.6))
bars = ax.barh(names, vals, color=["#9e9e9e" if v == 0 else "#1a73e8" for v in vals])
ax.axvline(0.70, color="#d32f2f", linestyle="--", label="phishing override (0.70)")
for b, v in zip(bars, vals):
    ax.text(v + 0.01, b.get_y() + b.get_height() / 2, f"{v:.2f}", va="center")
ax.set_xlabel("url_risk")
ax.set_title("Measured URL risk by signal")
ax.legend(fontsize=8)
fig.tight_layout()
fig.savefig(os.path.join(FIG, "url_risk.png"), bbox_inches="tight")
plt.close(fig)
print("saved", os.path.join(FIG, "url_risk.png"))
print("DONE — figures in assets/figures/")
