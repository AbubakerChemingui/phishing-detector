"""
quick_check.py – compute detection rates for adversarial suite.
"""
import os
import sys
sys.path.insert(0, os.path.dirname(__file__))

import core
import url_analysis

core.load_artifacts()
MODEL = core.MODEL
VECTORIZER = core.VECTORIZER
clean_email_text = core.clean_email_text

def _predict_raw(raw):
    cleaned = clean_email_text(raw)
    X = VECTORIZER.transform([cleaned])
    return float(MODEL.predict_proba(X)[0][1])

def detect_original(raw):
    return _predict_raw(raw) >= 0.5

def detect_hardened(raw):
    return core.analyze_email(raw, med_thresh=0.65, high_thresh=0.85, harden_first=False)["prediction"] == "Phishing"

# Simple adversarial samples (just a few)
samples = [
    ("Subject: Test\n\nhttp://secure-login-update-verify.com/login", True),
    ("Subject: Hello\n\nInvoice attached", False),
]

for txt, exp in samples:
    o = detect_original(txt)
    h = detect_hardened(txt)
    print(f"Sample: {txt[:30]}... orig:{o} hard:{h} exp:{exp}")

# Now compute on a few generated variants
base = "Subject: URGENT: Your Account Has Been Suspended!\n\nDear user,\n\nWe have detected suspicious activity on your account. Your access will be permanently terminated within 24 hours unless you verify your identity immediately.\n\nPlease click the link below to secure your account:\nhttp://secure-login-update-verify.com/login\n\nThank you,\nSecurity Department"
variants = [
    ("Base", base),
    ("Homograph", base.replace('secure-login-update-verify.com', 'ѕесure-login-update-ѵerify.com')),
    ("HexIP", base.replace('http://secure-login-update-verify.com/login', 'http://31.32.33.34/login')),
    ("Shortener", base.replace('http://secure-login-update-verify.com/login', 'http://bit.ly/xyz')),
    ("OpenRedirect", base.replace('http://secure-login-update-verify.com/login', 'http://google.com/url?q=http://secure-login-update-verify.com/login')),
    ("BenignWord", base.replace('Please click the link below', 'Please note this is routine. Please click the link below')),
]
print("\nVariant detection:")
for name, v in variants:
    o = detect_original(v)
    h = detect_hardened(v)
    print(f"{name:12} orig:{o} hard:{h}")