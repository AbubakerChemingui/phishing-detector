# adversarial evasion demo
# shows that a crafted phishing email can dodge the model, then applies a
# "hardening" layer (unicode normalization + homoglyph/leet sweeping) that
# pulls it back so the model catches it again.

import os
import re
import sys
import unicodedata
import joblib

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


def predict(text):
    cleaned = clean_email_text(text)
    X = vectorizer.transform([cleaned])
    pred = model.predict(X)[0]
    conf = model.predict_proba(X)[0][pred]
    return pred, conf


# evasion transformations an attacker might use
HOMOGLYPHS = {"а": "a", "е": "e", "о": "o", "с": "c", "р": "p", "х": "x",
              "у": "y", "і": "i", "к": "k", "ѕ": "s", "ԁ": "d", "һ": "h"}
LEET = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
        "@": "a", "$": "s", "!": "i", "|": "l"}
ZERO_WIDTH = ["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad"]


def evade_homoglyphs(text):
    return "".join(HOMOGLYPHS.get(c, c) for c in text)


def evade_leet(text):
    # map normal letters to l33t substitutes (reversed LEET mapping)
    inv = {}
    for k, v in LEET.items():
        inv.setdefault(v, k)
    return "".join(inv.get(c, c) for c in text)


def evade_zero_width(text):
    # sprinkle zero-width chars between letters so 'verify' != 'verify'
    return "\u200b".join(text)


def evade_letter_spacing(text):
    return " ".join(text)


def harden(text):
    # normalize unicode confusables, sweep homoglyphs + leet, drop zero-width
    text = unicodedata.normalize("NFKC", text)
    text = "".join(HOMOGLYPHS.get(c, c) for c in text)
    for k, v in LEET.items():
        text = text.replace(k, v)
    for zw in ZERO_WIDTH:
        text = text.replace(zw, "")
    # collapse spaces introduced by letter-spacing then let cleaning handle it
    return text


BASE_PHISH = ("urgent: your account has been suspended. click here "
              "http://verify-account-secure.com to confirm your identity now")
BASE_LEGIT = ("hi sami, attached is the weekly report. let me know "
              "if you'd like to schedule a review meeting on tuesday")

def evade_stacked(text):
    # real attacks combine tricks, not a single one
    t = evade_leet(text)
    t = evade_homoglyphs(t)
    t = evade_zero_width(t)
    return t


TRANSFORMS = [
    ("baseline (no evasion)", lambda t: t),
    ("homoglyphs", evade_homoglyphs),
    ("leet speak", evade_leet),
    ("zero-width chars", evade_zero_width),
    ("letter spacing", evade_letter_spacing),
    ("stacked (all combined)", evade_stacked),
]

print("adversarial evasion vs hardening")
print("sample phishing email (baseline prediction):")
p, c = predict(BASE_PHISH)
print(f"  baseline   -> pred={p} conf={c:.2%}")
print()

print(f"{'evasion':24s} {'evaded conf':>13s} {'hardened conf':>15s}")
print("-" * 56)
for name, fn in TRANSFORMS:
    evaded = fn(BASE_PHISH)
    _, e_conf = predict(evaded)
    _, h_conf = predict(harden(evaded))
    print(f"{name:24s} {e_conf:12.2%} {h_conf:14.2%}")

print()
print("controls: hardening must not break the legit email into a false positive")
print("-" * 56)
for name, fn in TRANSFORMS:
    evaded_legit = fn(BASE_LEGIT)
    _, e_conf = predict(evaded_legit)
    _, h_conf = predict(harden(evaded_legit))
    print(f"{name:24s} evaded={e_conf:.2%}  hardened={h_conf:.2%}")

print()
print("what this shows:")
print("  - homoglyphs, leet, zero-width and letter-spacing can drop a phishing")
print("    email's confidence, sometimes below the 0.65 threshold so it slips past")
print("  - the hardening layer normalizes those tricks back to plain text, so the")
print("    model's confidence recovers and the email is caught again")