# Data sources & provenance

## Training data (present in `data/`, intentionally untracked)

- `data/cleaned_emails.csv` — 82,189 rows (`clean_text`, `label` 0/1:
  42,847 phishing / 39,342 legit). Built by `preprocess.py` from the
  English-language `phishing_email.csv` corpus (classic Kaggle phishing-email
  dataset). **Every model in this repo was trained on this file** with
  `train_test_split(test_size=0.2, random_state=42, stratify=y)`, so the exact
  training split is reproducible — see `evaluate_saved_model.py`.
- `data/validation/Phishing_Email.csv` — 18,650 rows (`Email Text`,
  `Email Type`: 7,328 phishing / 11,322 safe). Unseen cross-dataset holdout.
- `data/validation/phish.zip` — archived copy of a phishing corpus.
- `data/multilingual_sample.csv` — 22 hand-written French + Arabic emails
  (11 FR: 6 phish / 5 legit; 11 AR: 6 phish / 5 legit). Demo/evaluation
  sample only — far too small to train on. See `evaluate_languages.py`.

## Canonical location of the original corpora

The full raw corpora (Enron, Ling-Spam, SpamAssassin, Nazario, Nigerian
fraud, CEAS-08, plus `phishing_model.pkl` / `naive_bayes_*.pkl` /
`tfidf_vectorizer.pkl` from earlier experiments) live in the old project
copy and were never moved:

```
C:\Users\Abubaker\phishing-detector\data\
C:\Users\Abubaker\phishing-detector\*.pkl
```

## Why big files are not in git

`.gitignore` excludes `*.pkl`, `data/*.csv`, `data/validation/`, `*.zip`
(deliberate): GitHub rejects files over 100 MB, and the corpora are
third-party public datasets. Nothing is lost — the files above document
exactly where each artifact lives and how to reproduce every number.

Committed (small, reproducible): all code, `results/*.json`,
`adversarial_results.txt`, reports, docs, `test_samples/`.
