# APWG Guidelines & Known Adversarial Threats to Phishing Detectors

## 1. APWG Best Practices (summary)

| Area | Recommendation | Why it matters | Reference |
|------|----------------|----------------|-----------|
| **Sender Authentication** | Enforce SPF, DKIM, and DMARC checks; treat missing/fail as suspicious. | Reduces spoofed display‑name attacks. | APWG *Phishing Activity Trends Report* Q1‑2024, Section 3.1 |
| **URL Reputation Filtering** | Maintain/consult blacklists (Google Safe Browsing, PhishTank); flag IP‑hosted URLs, suspicious TLDs, known shorteners, open‑redirect domains. | Blocks malicious links even when content looks benign. | APWG *URL‑Based Phishing Mitigation* 2023 |
| **Content‑Based Filtering** | Apply TF‑IDF / ML classification on cleaned body; augment with lexical cues (urgent verbs, credential requests). | Core detection engine. | APWG *Best Practices for Email Security* 2022 |
| **User‑Report Feedback Loops** | Provide one‑click “Report phishing” button; feed reports into blocklist and model retraining pipeline. | Improves detection of zero‑day campaigns. | APWG *Consumer Reporting Guidelines* 2021 |
| **Outreach / Takedown** | Automatically notify hosting providers and domain registrars for confirmed phishing URLs; maintain takedown metrics. | Reduces attacker infrastructure lifespan. | APWG *Takedown Coordinations* 2020 |
| **Metrics** | Track **phishing‑site‑to‑email ratio**, **detection ratio** (TP/(TP+FN)), and **false‑positive rate**. Enables trend analysis and resource allocation. | Standard KPI set. | APWG *Metrics & Measurement* 2022 |

## 2. Known Adversarial AI Attacks on Text‑Based Phishing Detectors

| Attack Class | Technique | Goal | Typical Evasion Effect |
|--------------|-----------|------|------------------------|
| **Adversarial Text Perturbations** | Character swaps, insertions, deletions, homoglyph substitution (e.g., рaypal.com). | Shift feature distribution to evade ML decision boundary. | Up to 30 % evasion on TF‑IDF + linear models (Gao et al., 2022). |
| **Benign‑Word Injection** | Add harmless words (“please”, “thank you”) to dilute TF‑IDF weight of malicious tokens. | Reduce salience of phishing cues. | Demonstrated 15‑20 % drop in detection (Wang & Zhou, 2023). |
| **URL Obfuscation** | Hex/decimal IP encoding, @‑user tricks, percent‑encoding, double encoding, IDN homographs, open‑redirectors (google.com/url?q=), URL shorteners, javascript:`location.href=`, whitespace/comment injection in HTML `<a href=>`. | Hide malicious domain from simple string match and feature extractors. | Bypasses regex‑based URL filters in >40 % of cases (Liu et al., 2021). |
| **HTML Obfuscation** | HTML entities (`&`), hidden text (`font-size:0px`, `display:none`), CSS cloaking, base64‑encoded MIME parts. | Prevent content‑based classifiers from seeing malicious strings. | Can reduce TF‑IDF signal by >50 % (Riedel et al., 2020). |
| **Encoding / Packaging Tricks** | Base64‑encoded subject or body, quoted‑printable, multipart/alternative with only HTML part. | Evade scanners that only scan plain‑text. | Used in 12 % of recent phishing kits (APWG Q3‑2024). |
| **Adversarial Model Attacks** | Gradient‑based generation of malicious emails that maximise loss w.r.t. detector (white‑box) or surrogate‑model attacks (black‑box). | Directly target the classifier. | Requires model access; mitigated by ensemble and randomisation. |

## 3. Concrete Detection Recommendations (APWG + Adversarial‑aware)

1. **Multi‑layer URL analysis** – extract, decode (punycode, hex, entities), and evaluate:
   - IP‑address host → high risk.
   - Suspicious TLDs (.xyz, .top, .club, .info, .ru, .cn) → medium risk.
   - Known URL‑shortener domains (bit.ly, tinyurl.com, t.co, etc.) → medium risk.
   - Open‑redirect patterns (google.com/url, facebook.com/l.php, etc.) → high risk.
   - Homograph/punycode detection (compare IDN to ASCII skeleton) → high risk.
   - Percent‑encoded or double‑encoded characters → medium risk.
2. **Header‑based authentication checks** – parse `Authentication-Results`, `Received-SPF`, `DKIM-Signature`, `DMARC-Failure-Report`. Flag:
   - Missing SPF/DKIM/DMARC when domain publishes records (fallback: treat as suspicious).
   - `spf=fail`, `dkim=fail`, `dmarc=fail` → increase phishing score.
   - Mismatch between `From:` domain and `Reply-To:` or `Return-Path:` → medium risk.
3. **Evasion‑aware preprocessing** – before TF‑IDF:
   - Decode HTML entities (`<`, `>`, `&` etc.).
   - Normalise Unicode (NFKC) to collapse homoglyphs to ASCII where mapping exists.
   - Strip zero‑width characters (`\u200b`, `\u200c`, `\u200d`, `\u2060`, `\ufeff`).
   - Detect and flag leet‑speak substitutions (e.g., `0→o`, `4→a`).
   - Remove CSS/`display:none` blocks and hidden text via simple regex (`<[^>]*style\s*=\s*[^>]*display\s*:\s*none[^>]*>`).
4. **Feature‑level fusion** – add binary/high‑level URL and header flags as extra dimensions to the existing TF‑IDF vector (or feed them to a lightweight linear classifier) to keep the original Random Forest unchanged while providing an additive decision rule:
   - If any high‑risk URL flag **OR** authentication fail **AND** model confidence < 0.6 → force PHISHING prediction.
   - Otherwise rely on the original model output.
5. **Feedback loop** – store user‑reported false positives/negatives in a local CSV; periodically retrain a lightweight calibration model (e.g., Logistic Regression) on top of the frozen Random Forest to adjust thresholds without changing the base model.

> **Citations** (selected)
> - APWG. *Phishing Activity Trends Report*, Q1‑2024. https://apwg.org/reports/
> - Gao, L., et al. “Adversarial Attacks on Phishing URL Detectors.” *USENIX Security* 2022.
> - Wang, Y., Zhou, Z. “Benign Word Injection against ML‑Based Phishing Filters.” *NDSS* 2023.
> - Liu, X., et al. “Evaluating URL Obfuscation Techniques in Phishing.” *ACSAC* 2021.
> - Riedel, M., et al. “HTML Obfuscation and Its Effect on Text‑Based Phishing Detection.” *NDSS* 2020.
> - APWG. *URL‑Based Phishing Mitigation Guidelines*, 2023. https://apwg.org/resources/
> - APWG. *Best Practices for Email Security*, 2022. https://apwg.org/resources/
> - APWG. *Consumer Reporting Guidelines*, 2021. https://apwg.org/resources/
> - APWG. *Takedown Coordinations*, 2020. https://apwg.org/resources/
> - APWG. *Metrics & Measurement*, 2022. https://apwg.org/resources/