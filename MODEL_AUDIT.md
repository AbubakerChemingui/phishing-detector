# Model Audit Report — senior review (measured 2026-09-18)

All numbers below were produced by `audit_models.py`
(`results/model_audit.json`) on the venv Python 3.13 / sklearn 1.9.0.
Re-run: `<venv-python> audit_models.py` from the repo root.

## 1. Artifacts

| Model | Type | Config | Features / vocab | Consistent | Size | Location | Role |
|---|---|---|---|---|---|---|---|
| Random Forest | `RandomForestClassifier` | 200 trees, unbounded depth | 5000 / 5000 unigrams, english stopwords | yes | 133.6 MB | repo root | **DEPLOYED** |
| XGBoost | `XGBClassifier` | 200 trees, max_depth 6 | same TF-IDF config | yes | 0.4 MB | old copy | stale reference |
| Naive Bayes | `MultinomialNB` | — | same TF-IDF config | yes | 0.2 MB | old copy | reference |

All three load cleanly (no version errors). Classes are `[0, 1]` (1 = phishing)
everywhere. (`<venv-python>` =
`C:\Users\Abubaker\phishing-detector\phishing_env\Scripts\python.exe`.)

## 2. Metric reproduction

Holdout = exact replay of the training split (`cleaned_emails.csv`, 80/20,
seed 42, stratify, n = 16,438). Cross = unseen `Phishing_Email.csv`
(n = 18,630). French-report claims compared field by field.

| Model | Holdout acc / prec / rec / F1 | Cross acc / prec / rec / F1 | French report | Verdict |
|---|---|---|---|---|
| RF | **98.59 / 98.85 / 98.44 / 98.64**, FPR 1.25% | **97.89 / 95.67 / 99.10 / 97.35**, FPR 2.90% | both tables | **EXACT match (diff 0.0000)** |
| XGB | 96.16 / 98.39 / 94.17 / 96.23, FPR 1.68% | 96.36 / 92.26 / 99.01 / 95.52, FPR 5.36% | Table 36 row was stale (98.55 / 98.16 / 99.08 / 98.62, artifact predates a data refresh) — **corrected in the report to the re-measured values**; gap row updated (+0.20 / -0.71); discussion rewritten | now matches |
| NB | 96.24 / 97.66 / 95.06 / 96.35, FPR 2.48% | 93.49 / 92.04 / 91.31 / 91.67, FPR 5.10% | both tables | **EXACT match (diff 0.0000)** — Table 36 is holdout, Table 38 is cross; both correct as labeled |

Consequences: every published number now reproduces to 4 decimals
(`audit_models.py` prints `match=True` on all six checks). RF stays deployed
(best holdout and cross scores, lowest FNs/FPs). The audit script itself
guards the report: re-running it fails loudly if any table drifts again.

## 3. Leakage analysis

- Exact-duplicate `clean_text` rows in corpus: 1,756 / 82,189 (2.1%).
- Test rows also present verbatim in train: 437 / 16,438 (**2.66%**).
- RF accuracy excluding overlapped rows: **98.55%** vs 98.59% overall.
- Leakage inflates accuracy by **0.04pp — negligible**. The 98.59% is genuine.

## 4. Threshold analysis (RF, holdout)

| Decision threshold | Recall | FPR | Flag rate |
|---|---|---|---|
| 0.50 | 98.54% | 1.26% | 52.0% |
| 0.65 (MEDIUM tier) | 95.36% | 0.53% | 50.0% |
| 0.85 (HIGH tier) | 83.15% | 0.15% | 43.4% |

The 0.65/0.85 alert tiers in `core.py` are justified: 0.65 halves the FPR
for ~3pp of recall. Nuance for the defense: `analyze_email` classifies by
argmax; these thresholds drive the alert tiers (and the `conf < 0.60` auth
override gate), not the raw label.

## 5. Calibration and edge behavior (RF)

- Mean confidence in the *predicted* label: **0.931 when right, 0.617 when
  wrong** — well separated; only 2.32% of predictions fall below 0.60.
- Empty / whitespace / Arabic input (cleaned to length 0): proba **0.863 →
  PHISHING**. Fail-closed default: garbage defaults to flagged. Defensible
  for a firewall, must be disclosed.
- Single word "hello": proba **0.984 → PHISHING**. Short-text phishing bias
  (same root cause as the "Happy Birthday!" legit-control FP).
- Bare URL-only email (`http://secure-login-update-verify.com/login`):
  proba 0.258 → Legitimate (**miss**, documented in SECURITY_REPORT §5).

## 6. Multilingual (from `evaluate_languages.py`)

English-only pipeline by construction (`[^a-z]` cleaning, english stopwords,
English training corpus). French: 54.5% accuracy, 5/5 legit flagged.
Arabic: 54.5% accuracy, 11/11 destroyed by cleaning. Documented limitation,
not a defect of the English model. (`results/multilingual_metrics.json`.)

## 7. Recommendations (priority order)

- P0: none blocking — the deployed model is sound, leakage negligible,
  calibration healthy.
- P1 (report hygiene — DONE): the French report's stale XGB internal row was
  replaced with re-measured values, its gap row recomputed, and the two
  discussion paragraphs rewritten; `audit_models.py` now checks all six
  table/claim pairs automatically.
- P2 (disclosure): fail-closed empty-input policy, bare-URL gap, short-text
  bias — all already listed in SECURITY_REPORT.md §5.
- P3 (future work): FR/AR pipeline, threshold recalibration with FP data,
  live-IMAP validation.
