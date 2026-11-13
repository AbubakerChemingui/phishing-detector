# Phishing Email Detection System

An end-to-end phishing detector built during a Vermeg internship: a TF-IDF + machine-learning
classifier, an additive hardening layer (URL reputation, SPF/DKIM/DMARC headers, Unicode
normalization), and four interfaces sharing one detection core — IMAP firewall, desktop GUI,
Streamlit web app, and CLI.

Every metric in this README is produced by committed scripts and checked by `audit_models.py`.
Nothing is estimated by hand.

---

## Table of contents

- [Results at a glance](#results-at-a-glance)
- [How it works](#how-it-works)
- [Model comparison and why Random Forest](#model-comparison-and-why-random-forest)
- [Hardening layer](#hardening-layer)
- [Interfaces](#interfaces)
- [Installation](#installation)
- [Data and model artifacts](#data-and-model-artifacts)
- [Reproducing every number](#reproducing-every-number)
- [Limitations (measured, not guessed)](#limitations-measured-not-guessed)
- [Documentation](#documentation)
- [Project structure](#project-structure)
- [Author](#author)

---

## Results at a glance

**Training corpus** — 82,189 emails (42,847 phishing / 39,342 legitimate), stratified 80/20
split with seed 42 → 16,438-email holdout.

**Unseen corpus** — 18,650 rows from an independent dataset, 18,630 usable after cleaning
(7,308 phishing / 11,322 legitimate). Never trained on.

| Model | Holdout accuracy | Holdout F1 | Unseen accuracy | Unseen F1 | Unseen FN | Unseen FP |
|---|---|---|---|---|---|---|
| **Random Forest (deployed)** | **98.59 %** | **98.64 %** | **97.89 %** | **97.35 %** | **66** | **328** |
| XGBoost | 96.16 % | 96.23 % | 96.36 % | 95.52 % | 72 | 607 |
| Naive Bayes | 96.24 % | 96.35 % | 93.49 % | 91.67 % | 635 | 577 |

Random Forest on the holdout: precision 98.85 %, recall 98.44 %, ROC-AUC 0.9988,
TN 7,770 / FP 98 / FN 134 / TP 8,436, FPR 1.25 %.

Random Forest on the unseen corpus: precision 95.67 %, recall 99.10 %, ROC-AUC 0.9958,
TN 10,994 / FP 328 / FN 66 / TP 7,242, FPR 2.90 %.

> **Security is not absolute.** These figures describe performance on two fixed corpora.
> The system reduces risk; it does not eliminate it.

---

## How it works

```
raw email
   │
   ├─ optional hardening ── Unicode NFKC + homoglyph / leet / zero-width normalization
   │
   ├─ cleaning ──────────── lowercase · URLs → "url" token · keep a–z only
   │
   ├─ TF-IDF ────────────── 5,000 unigrams, English stopwords
   │
   ├─ classifier ────────── Random Forest (200 trees, scikit-learn)
   │
   ├─ additive signals ──── URL risk score · SPF/DKIM/DMARC headers
   │
   └─ verdict ───────────── Phishing / Legitimate + confidence + tier + top words
```

The same `core.analyze_email()` path serves every interface, so a verdict cannot differ
between the GUI, the web app, the CLI, and the firewall.

**Explainability:** each verdict returns the top contributing words. For a measured sample
phishing email the output was: `account`, `click`, `subject`, `url`, `dear`, `urgent`,
`detected`, `link` (verdict: Phishing, 89.00 %).

---

## Model comparison and why Random Forest

All three models were trained on identical TF-IDF features and evaluated on the same two
corpora. Two conclusions follow from the tables above:

1. **Random Forest wins both evaluations** — 98.59 % on the holdout versus 96.16 % (XGBoost)
   and 96.24 % (Naive Bayes), and 97.89 % on unseen data versus 96.36 % and 93.49 %.
2. **It makes the fewest dangerous errors** — 66 false negatives versus 72 and 635, and the
   fewest false positives, 328 versus 607 and 577, on the unseen corpus.

Generalization gaps (unseen minus holdout accuracy): **Random Forest −0.70 pp, XGBoost +0.20 pp,
Naive Bayes −2.75 pp**. All three are small; Random Forest offers the best balance of accuracy,
error profile, and stability, so the choice was driven by out-of-distribution behavior rather
than by the highest in-sample score.

**Why not deep learning or a small language model?** With 82k tabular samples on a TF-IDF task,
tree ensembles win on accuracy per unit of cost: they train in minutes on CPU and every decision
is explainable through feature importances. A transformer would need 10–100× more data to
compete here and would sacrifice the auditability the project requires.

**Leakage check:** 437 holdout rows (2.66 %) also appear in training; removing them changes
accuracy by 0.04 pp (98.55 % vs 98.59 %), so the result is not leakage-driven.

---

## Hardening layer

Hardening is **additive and never touches the model**. It can only add suspicion signals or
normalize the input; the classifier and its weights are unchanged.

| Signal | Weight | Notes |
|---|---|---|
| Encoded IP host (hex / decimal / percent) | 0.30 | Obfuscated numeric hosts are almost never legitimate |
| Plain IP host | 0.30 | |
| Suspicious TLD | 0.20 | |
| URL shortener | 0.15 | |
| Open redirect | 0.15 | |
| Userinfo `@` trick | 0.05 | |

Decision rules layered on top of the model score:

- **URL override** — URL risk > 0.70 forces a Phishing verdict regardless of the text score.
- **Auth-fail override** — SPF/DKIM/DMARC failure with model confidence < 0.60 forces Phishing.
- **Authenticated-sender veto** — fully authenticated mail from a known service, clean URLs,
  and confidence < 0.80 is treated as legitimate (hard URL evidence always wins).
- **Forwarded mail** — the inner message is analyzed separately and the more suspicious verdict
  is kept, so forwarding a phish to a colleague does not launder it.

The audit found and fixed real bugs: hex-encoded IPs previously scored 0.00, and the `@`-trick
detector required two `@` signs to fire.

### Adversarial evaluation

A deterministic 40-sample suite covers homoglyphs, leet substitutions, zero-width characters,
URL obfuscation, and stacked combinations:

```
Original model only : 100.0% (40/40)
Hardened (URL+Header): 100.0% (40/40)
Improvement         : 0.0 percentage points
Legitimate controls : 15 emails → 1 false positive (6.7%, short benign text)
```

**Honest reading:** the model already caught the entire suite, so hardening produced **zero
regression, not a gain**. It is defense-in-depth against evasion families the model has not
seen — it is not a detection-rate improvement, and it is not presented as one.

---

## Interfaces

| Interface | File | Purpose |
|---|---|---|
| IMAP firewall | `email_firewall.py` | Scans an inbox, moves phishing to Spam, writes an audit log |
| Desktop GUI | `gui_app.py` | Analyst console with confidence tiers and top words |
| Web app | `app.py` | Streamlit front end for browser use |
| CLI demo | `demo.py` | Interactive terminal prompt: paste an email, finish with `END` |

Quick start:

```powershell
# 1. Offline check — no credentials required
python email_firewall.py --scan-folder test_samples
#   legit.eml: Legitimate (85.00 %)
#   phish.eml: Phishing (91.50 %)

# 2. Desktop GUI (sanity check without opening a window)
python gui_app.py --test

# 3. Web app
streamlit run app.py

# 4. Live IMAP scan (Gmail app password in environment variables)
$env:EMAIL_ADDRESS="you@gmail.com"
$env:EMAIL_PASSWORD="your-app-password"
python email_firewall.py --loop 300
```

The firewall supports `--harden`, `--verbose`, `--loop SECONDS`, `--max-retries`, and
`--scan-folder`. Its phishing gate defaults to **0.60** and can be overridden with
`PHISHING_CONFIDENCE_THRESHOLD`; every action is appended to `firewall.log`.

---

## Installation

Python 3.13 (developed and tested on 3.13.1, Windows).

```powershell
git clone https://github.com/AbubakerChemingui/phishing-detector.git
cd phishing-detector
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

`requirements.txt` pins the exact working versions (scikit-learn 1.9.0, pandas 3.0.3,
NumPy 2.5.0, XGBoost 3.3.0, Streamlit 1.58.0).

---

## Data and model artifacts

The corpora and trained binaries are **intentionally not committed** (GitHub rejects files over
100 MB, and the datasets are third-party). This means a fresh clone contains all code but needs
these local files to run:

| Path | What it is |
|---|---|
| `data/cleaned_emails.csv` | 82,189-row training corpus |
| `data/validation/Phishing_Email.csv` | 18,650-row unseen corpus |
| `random_forest_model.pkl` + `random_forest_vectorizer.pkl` | Deployed model pair |
| `phishing_model.pkl` / `naive_bayes_*.pkl` | Comparison models |

To rebuild the deployed model from the training corpus:

```powershell
python preprocess.py        # raw corpus → data/cleaned_emails.csv
python train_random_forest.py   # → random_forest_model.pkl + vectorizer
```

Model provenance and dataset links are documented in [`DATA_SOURCES.md`](DATA_SOURCES.md).
No number in this README depends on a file that cannot be regenerated.

---

## Reproducing every number

| Command | Produces |
|---|---|
| `python evaluate_saved_model.py` | Holdout and unseen-corpus metrics for the deployed model → `results/*.json` |
| `python audit_models.py` | Recomputes all six published metric claims and prints `match=True` |
| `python test_adversarial.py` | 40-sample adversarial suite → `adversarial_results.txt` |
| `python evaluate_languages.py` | French/Arabic honesty probe → `results/multilingual_metrics.json` |
| `python -m pytest test_system.py -q` | Full test suite — **24 passed** |

`audit_models.py` is the guardrail: if a report and the code ever disagree, it fails loudly
with the exact numbers.

---

## Limitations (measured, not guessed)

1. **English-only by construction.** Cleaning keeps only `a–z` (`re.sub(r'[^a-z\s]', ' ', text)`),
   which erases Arabic script entirely and turns French into out-of-vocabulary text for an
   English TF-IDF vocabulary. Measured on a hand-written 22-email sample: **French 54.5 %,
   Arabic 54.5 %**, with 5/5 legitimate emails false-positived in each language and **11/11
   Arabic emails destroyed by cleaning**. The GUI reports *"No analyzable English text: this
   system only supports English e-mails"* rather than guessing. A genuine fix requires a
   separate multilingual pipeline or a translation pre-step — not a model retrain.
2. **Short benign texts can false-positive.** Roughly 1–3 % of legitimate mail is flagged;
   the adversarial controls show 1/15 (6.7 %) on very short messages such as "Happy Birthday".
3. **Bare-URL emails are missed.** A message whose entire content is a link carries almost no
   text signal and can pass the text classifier; URL scoring helps but does not fully close this.
4. **Live scanning tested on Gmail only.** The IMAP path was exercised manually against a test
   Gmail inbox; Outlook OAuth2 exists in `outlook_oauth.py` but is not part of the verified path.

No claim of 100 % detection or zero false positives is made anywhere in this repository.

---

## Documentation

| Document | Contents |
|---|---|
| [`TECHNICAL_REPORT.md`](TECHNICAL_REPORT.md) | Architecture, pipeline, full results, reproducibility |
| [`SECURITY_REPORT.md`](SECURITY_REPORT.md) | Threat model, verification truth table, trade-offs |
| [`MODEL_AUDIT.md`](MODEL_AUDIT.md) | Per-model audit, calibration, error analysis |
| [`PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md) | Internship brief, objectives, decisions |
| [`DATA_SOURCES.md`](DATA_SOURCES.md) | Dataset provenance and artifact locations |
| [`APWG_AND_THREATS.md`](APWG_AND_THREATS.md) | Phishing landscape reference notes |
| `GUIDE_EN.md` / `GUIDE_FR.md` / `GUIDE_AR.md` | User guides |

---

## Project structure

```
phishing-detector/
├── core.py                  # shared detection core (cleaning, hardening, verdict)
├── url_analysis.py          # URL reputation scoring
├── preprocess.py            # raw corpus → cleaned_emails.csv
├── train_random_forest.py   # deployed model
├── train_xgboost.py         # comparison model
├── train_naive_bayes.py     # comparison model
├── email_firewall.py        # IMAP firewall + offline dry-run
├── gui_app.py               # desktop GUI
├── app.py                   # Streamlit web app
├── demo.py                  # CLI
├── evaluate_saved_model.py  # reproducible holdout + cross-corpus metrics
├── audit_models.py          # guards every published number
├── test_adversarial.py      # deterministic adversarial suite
├── evaluate_languages.py    # FR/AR honesty probe
├── test_system.py           # 24 unit/integration tests
├── results/                 # committed metric JSONs
└── test_samples/            # legit.eml + phish.eml for credential-free checks
```

---

## Author

**Abubaker Chemingui** — internship project, Vermeg, 2026.

Built with Python, scikit-learn, XGBoost, Tkinter, and Streamlit.
