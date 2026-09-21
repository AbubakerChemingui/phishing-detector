"""
core.py - Core logic for phishing email detection.
Contains preprocessing, model loading, and analysis functions.
Enhanced with APWG‑aligned URL analysis and header‑based authentication checks.
"""

import os
import re
import unicodedata
import joblib
import numpy as np
import pandas as pd

# URL analysis module (lightweight, rule‑based)
import url_analysis

# ---------------------------------------------------------------------------
# 1. Preprocessing & Hardening Pipeline
# ---------------------------------------------------------------------------
def clean_email_text(raw_text):
    raw_text = str(raw_text).lower()
    raw_text = re.sub(r'http\S+|www\S+', ' url ', raw_text)
    raw_text = re.sub(r'[^a-z\s]', ' ', raw_text)
    raw_text = re.sub(r'\s+', ' ', raw_text).strip()
    return raw_text


HOMOGLYPH_MAP = {
    # Cyrillic homoglyphs
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'К': 'K', 'М': 'M',
    'О': 'O', 'Р': 'P', 'Т': 'T', 'Х': 'X',
    # Greek homoglyphs
    'α': 'a', 'β': 'b', 'γ': 'y', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v',
    'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x',
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K',
    'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X'
}

LEET_MAP = {
    '0': 'o',
    '1': 'i',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '7': 't',
    '@': 'a',
    '$': 's',
    '!': 'i',
    '|': 'l'
}

ZERO_WIDTH_CHARS = {'\u200B', '\u200C', '\u200D', '\u2060', '\uFEFF', '\u00AD'}


def apply_hardening(text: str) -> str:
    """Apply normalization, homoglyph replacement, leet-speak decode, and strip zero-width chars."""
    if not text:
        return ""
    # 1. Unicode NFKC normalization
    text = unicodedata.normalize('NFKC', text)

    # 2. Remove zero-width characters
    text = "".join(ch for ch in text if ch not in ZERO_WIDTH_CHARS)

    # 3. Replace homoglyphs
    text = "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in text)

    # 4. Leet-speak mapping
    text = "".join(LEET_MAP.get(ch, ch) for ch in text)

    return text


def strip_html(html_str: str) -> str:
    """Strip basic HTML tags and entities."""
    clean = re.sub(r'<[^>]+>', ' ', html_str)
    clean = re.sub(r'&[a-zA-Z0-9#]+;', ' ', clean)
    return clean


# ---------------------------------------------------------------------------
# 2. Model & Vectorizer Management
# ---------------------------------------------------------------------------
MODEL = None
VECTORIZER = None
FEATURE_NAMES = None
FEATURE_IMPORTANCES = None

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(SCRIPT_DIR, "random_forest_model.pkl")
VECTORIZER_PATH = os.path.join(SCRIPT_DIR, "random_forest_vectorizer.pkl")


def load_artifacts():
    """Load model and vectorizer once at startup."""
    global MODEL, VECTORIZER, FEATURE_NAMES, FEATURE_IMPORTANCES
    if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
        raise FileNotFoundError(
            f"Required model files missing in {SCRIPT_DIR}:\n"
            f"- {os.path.basename(MODEL_PATH)}\n"
            f"- {os.path.basename(VECTORIZER_PATH)}"
        )

    MODEL = joblib.load(MODEL_PATH)
    VECTORIZER = joblib.load(VECTORIZER_PATH)

    if hasattr(VECTORIZER, "get_feature_names_out"):
        FEATURE_NAMES = VECTORIZER.get_feature_names_out()
    else:
        FEATURE_NAMES = np.array(VECTORIZER.get_feature_names())

    if hasattr(MODEL, "feature_importances_"):
        FEATURE_IMPORTANCES = MODEL.feature_importances_
    else:
        FEATURE_IMPORTANCES = np.ones(len(FEATURE_NAMES))


# ---------------------------------------------------------------------------
# 3. Helper functions for APWG‑aligned checks
# ---------------------------------------------------------------------------
def check_auth_headers(raw_text: str) -> bool:
    """
    Return True if authentication headers show explicit SPF/DKIM/DMARC fail.
    (We do not perform live DNS look‑ups; we rely on header signals only.)
    """
    text_lower = raw_text.lower()
    if 'spf=fail' in text_lower or 'dkim=fail' in text_lower or 'dmarc=fail' in text_lower:
        return True
    return False


def check_auth_pass(headers_text: str) -> bool:
    """
    Return True only if the headers show SPF+DKIM+DMARC *pass* together.
    This is positive evidence the message really came from its claimed
    sender (the opposite signal of check_auth_headers). Used as a veto
    against the model, never as the sole verdict.
    """
    text_lower = headers_text.lower()
    return ('dkim=pass' in text_lower and 'spf=pass' in text_lower
            and 'dmarc=pass' in text_lower)


def get_url_risk(raw_text: str) -> float:
    """Wrapper around url_analysis.get_url_risk for clarity."""
    return url_analysis.get_url_risk(raw_text)


# ---------------------------------------------------------------------------
# 4. Core Analysis Logic
# ---------------------------------------------------------------------------
def get_alert(pred_label: str, conf: float, med_thresh: float, high_thresh: float) -> str:
    if pred_label == "Phishing":
        if conf >= high_thresh:
            return "HIGH RISK - likely phishing"
        elif conf >= med_thresh:
            return "MEDIUM RISK - possibly phishing"
        else:
            return "LOW CONFIDENCE - uncertain, review manually"
    else:
        if conf >= high_thresh:
            return "SAFE - likely legitimate"
        elif conf >= med_thresh:
            return "LIKELY SAFE - probably legitimate"
        else:
            return "LOW CONFIDENCE - uncertain, review manually"


def get_risk_color(pred_label: str, conf: float, med_thresh: float, high_thresh: float) -> str:
    if pred_label == "Phishing":
        if conf >= high_thresh:
            return "#d32f2f"  # dark red
        elif conf >= med_thresh:
            return "#f57c00"  # orange
        else:
            return "#ffb300"  # amber
    else:
        if conf >= high_thresh:
            return "#388e3c"  # dark green
        elif conf >= med_thresh:
            return "#689f38"  # light green
        else:
            return "#ffb300"  # amber


def analyze_email(raw_text: str, med_thresh: float, high_thresh: float, harden_first: bool = False,
                  headers: str = "") -> dict:
    if MODEL is None or VECTORIZER is None:
        raise RuntimeError("Model and vectorizer are not loaded.")

    if harden_first:
        processed_input = apply_hardening(raw_text)
    else:
        processed_input = raw_text

    cleaned = clean_email_text(processed_input)

    if not cleaned or cleaned.strip() == "":
        return {
            "prediction": "-",
            "raw_pred": None,
            "confidence": 0.0,
            "confidence_str": "-",
            "alert": "Please enter e-mail text to analyse",
            "top_words": [],
            "color": "#666666"
        }

    # Transform
    X = VECTORIZER.transform([cleaned])

    # Predict
    pred_idx = MODEL.predict(X)[0]
    if hasattr(MODEL, "predict_proba"):
        probas = MODEL.predict_proba(X)[0]
        conf = float(probas[pred_idx])
    else:
        conf = 1.0

    # Assume 1 = Phishing, 0 = Legitimate (or string labels if encoded)
    if pred_idx in (1, "1", "Phishing", "phishing"):
        pred_label = "Phishing"
        raw_pred = 1
    else:
        pred_label = "Legitimate"
        raw_pred = 0

    # --- APWG‑aligned additive signals ---
    # URL reputation looks at content plus headers (e.g. List-Unsubscribe
    # links live in headers, not the body).
    url_scope = raw_text if not headers else raw_text + "\n" + headers
    url_risk = get_url_risk(url_scope)              # 0‑1
    # Auth signals come from headers when provided; otherwise fall back to
    # the full text (preserves old behavior for raw-.eml callers).
    auth_scope = headers if headers else raw_text
    auth_fail = check_auth_headers(auth_scope)      # bool
    auth_pass = check_auth_pass(auth_scope)         # bool

    # Override rule: if URL looks highly malicious OR we see an auth fail
    # and the model is not confident, force a phishing decision.
    if url_risk > 0.70 or (auth_fail and conf < 0.60):
        pred_label = "Phishing"
        raw_pred = 1
        # Boost confidence to at least high‑threshold level so UI shows strong alert
        conf = max(conf, 0.85)
    elif (auth_pass and url_risk < 0.50 and pred_label == "Phishing"
            and conf < 0.80):
        # Authenticated-sender veto: fully authenticated (SPF+DKIM+DMARC pass)
        # with clean URLs and only moderate model suspicion is legitimate
        # mail. Hard URL evidence (above) always wins over this veto, as does
        # high model confidence. Confidence stays honestly low:
        # authentication tipped an uncertain call.
        pred_label = "Legitimate"
        raw_pred = 0
        conf = 1.0 - conf
    alert_tier = get_alert(pred_label, conf, med_thresh, high_thresh)
    color = get_risk_color(pred_label, conf, med_thresh, high_thresh)

    # Top contributing words = TF-IDF * feature_importance
    top_words = []
    if FEATURE_NAMES is not None and FEATURE_IMPORTANCES is not None:
        coo = X.tocoo()
        contributions = []
        for col_idx, tfidf_val in zip(coo.col, coo.data):
            if tfidf_val > 0:
                score = float(tfidf_val * FEATURE_IMPORTANCES[col_idx])
                word = FEATURE_NAMES[col_idx]
                contributions.append((word, score))
        contributions.sort(key=lambda item: item[1], reverse=True)
        top_words = contributions[:8]

    return {
        "prediction": pred_label,
        "raw_pred": raw_pred,
        "confidence": conf,
        "confidence_str": f"{conf * 100:.2f} %",
        "alert": alert_tier,
        "top_words": top_words,
        "color": color
    }