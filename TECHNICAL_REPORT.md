# Phishing Email Detection System — Deep Technical Report

*Project: phishing email detector with SMTP firewall, APWG-aligned hardening,
and adversarial evaluation. All figures measured on 2026-09-18 from committed
code; every claim maps to a re-runnable command (§12).*

## 1. Executive summary

A TF-IDF + Random Forest classifier (200 trees, 5,000 features) detects
phishing emails at **98.59% accuracy / 1.25% false-positive rate** on a
16,438-email holdout and **97.89% / 2.90%** on an 18,630-email unseen corpus.
Rule-based hardening (URL reputation scoring, SPF/DKIM/DMARC header checks,
Unicode normalization) is layered additively over the model without touching
it. A deterministic 40-sample adversarial suite scores 40/40 before and after
hardening; 1 of 15 legitimate controls false-positives. The system is
English-only by construction (measured French/Arabic accuracy: 54.5%, with
Arabic fully destroyed by the cleaning step). An IMAP firewall routes every
message through the hardened pipeline and ships with a network-free dry-run
mode. All 18 unit tests pass.

## 2. Objectives and scope

1. Detect phishing emails with a calibrated ML classifier.
2. Harden detection against adversarial evasion (homoglyphs, leet-speak,
   zero-width characters, URL obfuscation: punycode, hex/decimal/percent
   encoded IPs, `@` userinfo tricks, shorteners, open redirects, HTML
   entities, base64 packaging, stacked combinations) per APWG best practices.
3. Serve predictions through four interfaces: desktop GUI, Streamlit web app,
   CLI, and an IMAP email firewall.
4. Prove every performance claim with committed, re-runnable code.

Out of scope (documented, §10): non-English detection, live takedown APIs,
attachment analysis, sender-domain reputation feeds.

## 3. System architecture

```
                    +----------------- email_firewall.py ------------------+
                    | IMAP inbox -> classify -> move confident phishing to Spam |
                    | --scan-folder dry-run (no network) | --harden flag  |
                    +------------------------+---------------------------+
                                             |
                    +------------------------v---------------------------+
                    | core.analyze_email()                                |
                    |  1. apply_hardening (optional): NFKC, homoglyph map, |
                    |     leet map, zero-width strip                      |
                    |  2. clean_email_text: lowercase, URL->'url' token,   |
                    |     [^a-z] removed, whitespace collapsed             |
                    |  3. TF-IDF (5000) + RandomForest -> proba, label    |
                    |  4. url_analysis.get_url_risk() -> 0..1             |
                    |  5. check_auth_headers() -> spf/dkim/dmarc fail?    |
                    |  6. ADDITIVE OVERRIDE: url_risk>0.70 OR (auth_fail   |
                    |     AND conf<0.60) => Phishing, conf boosted >=0.85 |
                    +------------------------+---------------------------+
                        |                |                |
                 gui_app.py          app.py            demo.py
              (Tkinter desktop)   (Streamlit web)       (CLI)
```

Interfaces share one detection core (`core.py`); the GUI re-exports it, the
Streamlit app and firewall call it directly, and the CLI uses the same
cleaning plus the saved artifacts.

## 4. Data

| Dataset | Rows | Phishing | Legit | Role |
|---|---|---|---|---|
| `data/cleaned_emails.csv` | 82,189 | 42,847 | 39,342 | training + holdout source |
| `data/validation/Phishing_Email.csv` | 18,650 (18,630 usable) | 7,308 | 11,322 | unseen cross-dataset holdout |
| `data/multilingual_sample.csv` | 22 (11 FR, 11 AR) | 12 | 10 | FR/AR probe (hand-written) |

Split: stratified 80/20, `random_state=42` — identical to the training
script, so the holdout below is the exact training-time test set
(train 65,751 / test 16,438; 8,570 positive / 7,868 negative in test).
Provenance and the intentional untracking of large binaries: `DATA_SOURCES.md`.

**Leakage analysis.** 1,756 exact-duplicate rows (2.1% of corpus); 437 of
16,438 test rows (2.66%) appear verbatim in train. Accuracy excluding
overlaps: 98.55% vs 98.59% overall — leakage contributes 0.04pp, negligible.

## 5. Models

| Model | Type | Config | Features | Size | Location |
|---|---|---|---|---|---|
| Random Forest (deployed) | `RandomForestClassifier` | 200 trees, unbounded depth | TF-IDF 5000 unigrams, english stopwords | 133.6 MB | repo root |
| XGBoost (reference) | `XGBClassifier` | 200 estimators, max_depth 6 | same | 0.4 MB | old project copy |
| Naive Bayes (reference) | `MultinomialNB` | — | same | 0.2 MB | old project copy |

All vectorizers verified consistent with their models (5,000 features,
classes `[0, 1]`), all load cleanly on scikit-learn 1.9.0 / Python 3.13.

## 6. Evaluation methodology

- **Holdout:** rebuild the exact training split (same file, dropna on
  `clean_text`, seed 42, stratify), transform with the *saved* vectorizer,
  predict with the *saved* model. No retraining (`evaluate_saved_model.py`).
- **Cross-dataset:** clean `Email Text` with the project regex, label from
  `Email Type`, same saved artifacts.
- **Decision rule everywhere:** phishing iff P(phishing) ≥ 0.5 unless stated.
- **Adversarial:** 40 deterministic samples (seed 12345; 20 evasion families
  over 3 templates, truncated to 40) + 15 legitimate controls; raw side uses
  plain-cleaned text, hardened side uses hardened text plus the URL/auth
  override (`test_adversarial.py` → `adversarial_results.txt`).
- **Languages:** per-language accuracy, legit FPR, phish recall, and a
  "destroyed by cleaning" counter (`evaluate_languages.py`).

## 7. Results

**Holdout (16,438 emails):**

| Model | Acc | Prec | Rec | F1 | AUC | TN/FP/FN/TP | FPR |
|---|---|---|---|---|---|---|---|
| RF | 98.59% | 98.85% | 98.44% | 98.64% | 99.88% | 7770/98/134/8436 | 1.25% |
| XGB | 96.16% | 98.39% | 94.17% | 96.23% | — | — | 1.68% |
| NB | 96.24% | 97.66% | 95.06% | 96.35% | — | — | 2.48% |

**Cross-dataset (18,630 emails):**

| Model | Acc | Prec | Rec | F1 | AUC | TN/FP/FN/TP | FPR |
|---|---|---|---|---|---|---|---|
| RF | 97.89% | 95.67% | 99.10% | 97.35% | 99.58% | 10994/328/66/7242 | 2.90% |
| XGB | 96.36% | 92.26% | 99.01% | 95.52% | — | 10715/607/72/7236 | 5.36% |
| NB | 93.49% | 92.04% | 91.31% | 91.67% | — | 10745/577/635/6673 | 5.10% |

RF generalizes best (accuracy gap −0.70pp vs −2.75pp NB; XGB gap +0.20pp on
re-measured figures). RF also has the fewest false negatives (66) and false
positives (328) externally — the deployment choice.

## 8. Threshold and calibration analysis (RF, holdout)

| Decision threshold | Recall | FPR | Flag rate |
|---|---|---|---|
| 0.50 | 98.54% | 1.26% | 52.0% |
| 0.65 (MEDIUM tier) | 95.36% | 0.53% | 50.0% |
| 0.85 (HIGH tier) | 83.15% | 0.15% | 43.4% |

The 0.65/0.85 alert tiers are empirically justified (0.65 halves FPR for ~3pp
recall). Note: `analyze_email` classifies by argmax; thresholds drive alert
tiers and the `conf < 0.60` auth-override gate. Mean confidence in the
predicted label is 0.931 when right vs 0.617 when wrong — the model separates
certainty well; only 2.32% of predictions fall below 0.60.

## 9. Hardening design and verification

URL risk is a weighted sum over detected signals per email (measured):
hex/decimal-encoded IP 0.30, plain IP host 0.30, suspicious TLD 0.20,
shortener 0.15, open redirect 0.15, percent-encoding 0.10, homograph 0.05,
general obfuscation 0.05 (capped at 1.0; clean URLs score 0.00; percent-IP
0.45). Verification during this project found and fixed four defects here:
hex-IP flags never entered the sum (scored 0.00), `@` detection required two
`@` characters, the percent-IP pattern could never match real encodings, and
mixed hex shapes (`c0a80101`) were missed. Text normalization (NFKC +
Cyrillic/Greek homoglyph map + leet map + zero-width strip) runs before the
model when `harden_first=True` (GUI toggle, firewall `--harden` flag,
adversarial suite). The firewall dry-run needs no credentials:
`legit.eml` → Legitimate (83.50%), `phish.eml` → Phishing (85.00%).

## 10. Adversarial and multilingual results (honest reading)

Adversarial: 40/40 raw and 40/40 hardened (Δ 0pp) across all 20 evasion
families. Stated plainly: the model already catches this suite, so hardening
contributes defense-in-depth (normalization + URL scoring), not a measured
detection gain here. Legit controls: 1/15 FP (6.7%) — `Control#8`
("Happy Birthday!"), flagged by model bias on short benign text with no URL
involved, not by any URL rule.

Multilingual: the pipeline is English-only by construction. French: 54.5%
accuracy, 5/5 legit flagged, 0/11 destroyed. Arabic: 54.5% accuracy, 11/11
destroyed by cleaning (predictions made on empty text). FR/AR support requires
a separate pipeline and is future work (§13).

## 11. Edge behavior and known limitations

1. Empty/whitespace/non-Latin-only input is refused, not classified ("No
   analyzable English text…"; demo refuses likewise). The underlying
   zero-vector model bias (proba 0.863 PHISHING on empty vectors) is measured
   in `MODEL_AUDIT.md` but unreachable through any interface.
2. Single common words ("hello") score ~0.98 PHISHING — short-text bias.
3. Bare-URL-only emails (no body) classify Legitimate (cleaning reduces them
   to the `url` token; no rule fires on plain `.com` domains).
4. Single weak URL signals (shortener alone: 0.15) do not cross the 0.70
   override by design; recalibration needs FP data.
5. Live IMAP scan exercised manually on a test Gmail account (moves, vetoes,
   threshold gate, loop scheduler, and audit log all verified live; see
   `firewall.log` format). Outlook OAuth2 path is code-complete but needs a
   first live sign-in.

## 12. Reproducibility

Interpreter: `C:\Users\Abubaker\phishing-detector\phishing_env\Scripts\python.exe`.
Dependencies: `requirements.txt` (pinned). From the repo root:

```powershell
<venv-python> -m pytest test_system.py -v          # 23 passed
<venv-python> evaluate_saved_model.py               # results/baseline_metrics.json + cross_dataset_metrics.json
<venv-python> test_adversarial.py                   # adversarial_results.txt
<venv-python> evaluate_languages.py                 # results/multilingual_metrics.json
<venv-python> audit_models.py                       # results/model_audit.json (all six claim checks match)
<venv-python> email_firewall.py --scan-folder test_samples [--harden]
```

Large binaries (`.pkl`, corpora) are intentionally untracked (GitHub 100 MB
limit, third-party licensing); metric JSONs are committed.

## 13. Conclusion and future work

The deployed Random Forest is strong, well-calibrated, and generalizes
(98.59% → 97.89% with FPR under 3% on unseen data); hardening adds
URL/header/text-normalization defenses without touching the model; every
limitation above is measured and documented rather than hidden. Recommended
next steps if scope expands: (a) a genuine FR/AR pipeline (translation
pre-step or per-script models), (b) threshold/weight recalibration against
collected false positives, (c) closing the bare-URL gap, (d) first live
Outlook OAuth2 sign-in and loop test, (e) sender-reputation layer for
attacker-authenticated mail (the one residual the content+auth design
cannot see — see SECURITY_REPORT.md §5 item 6).

## Appendix A — Amendments since initial issue

Features added after this report was first written (each verified, tested,
and committed; details in SECURITY_REPORT.md and MODEL_AUDIT.md):

- **Authenticated-sender veto** (`core.check_auth_pass`): SPF+DKIM+DMARC pass
  from a known service (google.com, accounts.google.com, microsoft.com,
  apple.com, amazon.com, env-extendable via `KNOWN_SENDERS`) with clean URLs
  and confidence < 0.80 returns Legitimate at honestly low confidence.
  Consumer domains are excluded (anyone can authenticate attacker@gmail.com).
- **Forwarded-content analysis** (`core.split_forwarded`,
  `analyze_email_with_forwarding`): inner message scored separately without
  outer headers; most-suspicious verdict wins; decoys cannot lower it.
- **Move-threshold gate**: live moves require `Phishing` at confidence ≥
  `PHISHING_CONFIDENCE_THRESHOLD` (default 0.65); marginal calls stay for
  human review.
- **Audit log**: every firewall verdict/action timestamped to `firewall.log`.
- **Outlook OAuth2** (`outlook_oauth.py`): device-code sign-in + XOAUTH2 IMAP
  (Microsoft killed password IMAP); Gmail path untouched.
- **Empty-input refusal** in demo/CLI matching the core; GUI Clear button
  resets thresholds; loop scheduler fixed (slept only on failure → busy-spin).
- **Byte-stable metrics**: evaluators round to 6 decimals (multithreaded BLAS
  flips the last bit between runs).
