"""
test_adversarial.py – Adversarial evaluation of the phishing detector.
Generates a deterministic suite of evasion‑based phishing samples and measures detection
rate before (model only) and after (model + APWG‑aligned URL/header hardening).
Also evaluates a set of legitimate control emails to compute false‑positive rate.
"""

import os
import sys
import random
import string
import base64
import urllib.parse
import re

# Ensure we can import from the local folder
sys_path = os.path.dirname(os.path.abspath(__file__))
if sys_path not in sys.path:
    sys.path.insert(0, sys_path)

import core
import url_analysis

# Load model & vectorizer once
core.load_artifacts()
MODEL = core.MODEL
VECTORIZER = core.VECTORIZER
clean_email_text = core.clean_email_text
analyze_email = core.analyze_email

# ----------------------------------------------------------------------
def _predict_raw(raw_text: str) -> float:
    """
    Return phishing probability from the base Random Forest model,
    using only the original cleaning (no URL/header checks).
    """
    cleaned = clean_email_text(raw_text)
    X = VECTORIZER.transform([cleaned])
    probas = MODEL.predict_proba(X)[0]
    # Assume class 1 = phishing
    return float(probas[1])


def detect_original(raw_text: str, threshold: float = 0.5) -> bool:
    """True if model predicts phishing (prob >= threshold)."""
    return _predict_raw(raw_text) >= threshold


def detect_hardened(raw_text: str, med_thresh: float = 0.65, high_thresh: float = 0.85) -> bool:
    """
    Use the full hardened logic from core.analyze_email.
    Returns True if prediction is Phishing.
    """
    result = analyze_email(raw_text, med_thresh=med_thresh, high_thresh=high_thresh, harden_first=False)
    return result["prediction"] == "Phishing"


# ----------------------------------------------------------------------
# Base phishing templates (subject + body)
# ----------------------------------------------------------------------
BASE_PHISHING = [
    {
        "subject": "URGENT: Your Account Has Been Suspended!",
        "body": ("Dear user,\n\nWe have detected suspicious activity on your account. "
                 "Your access will be permanently terminated within 24 hours unless you "
                 "verify your identity immediately.\n\nPlease click the link below to secure your account:\n"
                 "http://secure-login-update-verify.com/login\n\nThank you,\nSecurity Department")
    },
    {
        "subject": "Invoice # 987654321 – Payment Required",
        "body": ("Hello,\n\nPlease find attached the invoice for your recent purchase. "
                 "To avoid service interruption, kindly remit payment within 48 hours using the secure portal:\n"
                 "http://payments-quick-settle.net/pay\n\nIf you have any questions, reply to this email.\n\nBest regards,\nBilling Team")
    },
    {
        "subject": "Important: Update Your Payment Information",
        "body": ("Hi there,\n\nOur records show that your payment method is about to expire. "
                 "To continue enjoying uninterrupted service, please update your card details now:\n"
                 "http://update-payment-secure.com/update\n\nFailure to update may result in account suspension.\n\nThanks,\nCustomer Support")
    }
]

# ----------------------------------------------------------------------
# Helper transformation functions
# ----------------------------------------------------------------------
def homograph_attack(text: str) -> str:
    """Replace Latin letters in domain names with Cyrillic look‑alikes."""
    mapping = {'a': 'а', 'e': 'е', 'o': 'о', 'p': 'р', 'c': 'с', 'y': 'у', 'x': 'х'}
    def replace_word(match):
        word = match.group(0)
        return ''.join(mapping.get(ch, ch) for ch in word)
    return re.sub(r'[a-zA-Z]+(?:\.[a-zA-Z]+)+', replace_word, text, flags=re.IGNORECASE)


def hex_ip_attack(text: str) -> str:
    """Encode an IP address in hex within a URL."""
    def hex_encode_ip(match):
        ip = match.group(0)
        hex_ip = ''.join(f'{int(octet):02x}' for octet in ip.split('.'))
        return f'http://{hex_ip}/'
    return re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', hex_encode_ip, text)


def percent_ip_attack(text: str) -> str:
    """Encode an IP address in percent‑encoding within a URL."""
    def percent_encode_ip(match):
        ip = match.group(0)
        percent_ip = ''.join(f'%{int(octet):02X}' for octet in ip.split('.'))
        return f'http://{percent_ip}/'
    return re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', percent_encode_ip, text)


def shortener_attack(text: str) -> str:
    """Replace a suspicious domain with a known shortener."""
    return re.sub(r'https?://[^\s/]+', 'http://bit.ly/xyz123', text, count=1)


def open_redirect_attack(text: str) -> str:
    """Prepend an open‑redirector before the malicious URL."""
    def add_redirect(match):
        url = match.group(0)
        return f'https://google.com/url?q={urllib.parse.quote(url)}'
    return re.sub(r'https?://[^\s]+', add_redirect, text)


def benign_word_injection(text: str) -> str:
    """Insert a benign sentence before the malicious call‑to‑action."""
    benign = ("Please note that this is a routine service notification. "
              "Kindly disregard if you have already taken action. ")
    parts = text.split('\n', 1)
    if len(parts) == 2:
        return parts[0] + '\n' + benign + parts[1]
    else:
        return benign + text


def leet_speak_attack(text: str) -> str:
    """Apply leet‑speak substitution to the whole text."""
    leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
    return ''.join(leet_map.get(ch.lower(), ch) for ch in text)


def zero_width_attack(text: str) -> str:
    """Insert zero‑width characters between each character."""
    zw = '\u200b'
    return zw.join(text)


def char_swap_padding(text: str) -> str:
    """Swap adjacent characters in random words and add occasional spaces."""
    words = text.split()
    for i, w in enumerate(words):
        if len(w) > 3 and random.random() < 0.3:
            lst = list(w)
            pos = random.randrange(len(lst)-1)
            lst[pos], lst[pos+1] = lst[pos+1], lst[pos]
            words[i] = ''.join(lst)
        if random.random() < 0.1:
            words[i] = w + ' '
    return ' '.join(words)


def html_entity_obfuscation(text: str) -> str:
    """Replace < and > with HTML entities in any HTML-like tags."""
    return text.replace('<', '<').replace('>', '>')


def base64_encode_body(text: str) -> str:
    """Encode the body (after first blank line) in Base64 MIME style."""
    if '\n\n' in text:
        head, body = text.split('\n\n', 1)
        encoded = base64.b64encode(body.encode('utf-8')).decode('ascii')
        return f'{head}\n\nContent-Transfer-Encoding: base64\n\n{encoded}'
    else:
        encoded = base64.b64encode(text.encode('utf-8')).decode('ascii')
        return f'Content-Transfer-Encoding: base64\n\n{encoded}'


# ----------------------------------------------------------------------
# Build adversarial suite (deterministic with seed)
# ----------------------------------------------------------------------
def build_adversarial_samples(seed: int = 12345) -> list:
    """Return a list of (description, raw_text) tuples."""
    random.seed(seed)
    samples = []
    for idx, tmpl in enumerate(BASE_PHISHING):
        base = f"Subject: {tmpl['subject']}\n\n{tmpl['body']}"
        # 1. Clean baseline
        samples.append((f"Base#{idx+1}", base))
        # 2. Homograph
        samples.append((f"Homograph#{idx+1}", homograph_attack(base)))
        # 3. Hex/IP encoded
        samples.append((f"HexIP#{idx+1}", hex_ip_attack(base)))
        # 4. Percent‑encoded IP
        samples.append((f"PercentIP#{idx+1}", percent_ip_attack(base)))
        # 5. Shortener
        samples.append((f"Shortener#{idx+1}", shortener_attack(base)))
        # 6. Open redirect
        samples.append((f"OpenRedirect#{idx+1}", open_redirect_attack(base)))
        # 7. Benign word injection
        samples.append((f"BenignWord#{idx+1}", benign_word_injection(base)))
        # 8. Leet‑speak
        samples.append((f"LeetSpeak#{idx+1}", leet_speak_attack(base)))
        # 9. Zero‑width chars
        samples.append((f"ZeroWidth#{idx+1}", zero_width_attack(base)))
        # 10. Char swap/padding
        samples.append((f"CharSwap#{idx+1}", char_swap_padding(base)))
        # 11. HTML entity obfuscation
        samples.append((f"HTMLEntity#{idx+1}", html_entity_obfuscation(base)))
        # 12. Base64 encoded body
        samples.append((f"Base64Body#{idx+1}", base64_encode_body(base)))
        # 13. Combine homograph + shortener
        combined1 = shortener_attack(homograph_attack(base))
        samples.append((f"Combo1#{idx+1}", combined1))
        # 14. Combine open redirect + hex IP
        combined2 = open_redirect_attack(hex_ip_attack(base))
        samples.append((f"Combo2#{idx+1}", combined2))
        # 15. Combine leet + percent IP
        combined3 = percent_ip_attack(leet_speak_attack(base))
        samples.append((f"Combo3#{idx+1}", combined3))
        # 16. Combine zero‑width + HTML entity
        combined4 = html_entity_obfuscation(zero_width_attack(base))
        samples.append((f"Combo4#{idx+1}", combined4))
        # 17. Combine shortener + benign word
        combined5 = benign_word_injection(shortener_attack(base))
        samples.append((f"Combo5#{idx+1}", combined5))
        # 18. Combine homograph + leet + shortener
        combined6 = shortener_attack(leet_speak_attack(homograph_attack(base)))
        samples.append((f"Combo6#{idx+1}", combined6))
        # 19. Combine open redirect + base64 body
        combined7 = base64_encode_body(open_redirect_attack(base))
        samples.append((f"Combo7#{idx+1}", combined7))
        # 20. Combine percent IP + zero‑width + HTML entity
        combined8 = html_entity_obfuscation(zero_width_attack(percent_ip_attack(base)))
        samples.append((f"Combo8#{idx+1}", combined8))
    # Ensure we have at least 40 samples; if more, trim; if less, duplicate (should be 20*? Actually we have 3 base * 20 = 60)
    # We'll keep first 40 for consistency
    return samples[:40]


# ----------------------------------------------------------------------
# Legitimate control emails
# ----------------------------------------------------------------------
LEGIT_CONTROLS = [
    "Subject: Weekly Team Sync – Meeting Notes\n\nHi Team,\n\nPlease find the agenda attached.\n\nBest,\nAlice",
    "Subject: Your Monthly Newsletter – September 2026\n\nHello,\n\nWelcome to this month’s newsletter! Highlights include new product launch and upcoming webinar.\n\nRegards,\nMarketing",
    "Subject: Re: Receipt for Your Purchase\n\nHi John,\n\nThank you for your purchase. Please find the receipt attached.\n\nBest,\nStore Support",
    "Subject: Urgent: Server Maintenance Tonight at 2 AM\n\nHi all,\n\nThis is a heads‑up that we will perform scheduled maintenance on the database server tonight.\n\nPlease plan accordingly.\n\nThanks,\nIT Operations",
    "Subject: Invitation: Company Picnic – June 15\n\nYou're invited to our annual company picnic!\n\nDate: June 15, 2026\nLocation: Riverside Park\n\nKindly RSVP by June 10.\n\nHR Team",
    "Subject: Your Order #12345 Has Shipped\n\nHi Jane,\n\nYour order has shipped and is expected to arrive by Friday.\n\nTracking number: 1Z999AA10123456789\n\nThanks,\nShopify Store",
    "Subject: Reminder: Password Change Required\n\nHi there,\n\nAs part of our security policy, please change your password by end of day.\n\nThanks,\nSecurity Team",
    "Subject: Happy Birthday!\n\nWishing you a wonderful day filled with joy and cake!\n\nBest wishes,\nThe Team",
    "Subject: Request for Feedback on Latest Feature\n\nHi,\n\nWe would love to hear your thoughts on the new dashboard feature.\n\nPlease reply with any comments.\n\nThanks,\nProduct Team",
    "Subject: Notice: Office Closed Friday\n\nPlease note that the office will be closed this Friday due to a public holiday.\n\nStay safe,\nFacilities",
    "Subject: Your Subscription Renewal – Action Required\n\nHi,\n\nYour premium subscription is set to renew on July 1. Please review the attached invoice.\n\nThanks,\nBilling Department",
    "Subject: Security Alert: Suspicious Login Attempt Blocked\n\nHi,\n\nWe blocked a suspicious login attempt from an unfamiliar location.\n\nNo action is required on your part.\n\nThanks,\nSecurity Operations",
    "Subject: Update: New Privacy Policy Effective Soon\n\nPlease review our updated privacy policy linked below.\n\nhttps://www.example.com/privacy\n\nThanks,\nLegal Team",
    "Subject: Congratulations on Your Work Anniversary!\n\nCelebrating 5 years with us!\n\nThanks,\nHR",
    "Subject: You’ve Got a Gift Card!\n\nEnjoy your $25 gift card for our store.\n\nCode: GIFT25\n\nThanks,\nMarketing"
]

# ----------------------------------------------------------------------
# Run evaluation
# ----------------------------------------------------------------------
def main():
    # Adversarial evaluation
    adv_samples = build_adversarial_samples()
    total_adv = len(adv_samples)
    orig_detects = 0
    hard_detects = 0
    orig_misses = []
    hard_misses = []

    print(f"Evaluating {total_adv} adversarial samples (seed=12345)...")
    for desc, raw in adv_samples:
        orig = detect_original(raw)
        hard = detect_hardened(raw)
        if orig:
            orig_detects += 1
        else:
            orig_misses.append(desc)
        if hard:
            hard_detects += 1
        else:
            hard_misses.append(desc)

    orig_rate = orig_detects / total_adv * 100 if total_adv else 0
    hard_rate = hard_detects / total_adv * 100 if total_adv else 0

    print("\n=== Adversarial Detection Rates ===")
    print(f"Original model only : {orig_rate:.1f}% ({orig_detects}/{total_adv})")
    print(f"Hardened (URL+Header): {hard_rate:.1f}% ({hard_detects}/{total_adv})")
    print(f"Improvement         : {hard_rate - orig_rate:.1f} percentage points")
    print("\nOriginal misses:", ", ".join(orig_misses) if orig_misses else "None")
    print("Hardened misses:", ", ".join(hard_misses) if hard_misses else "None")

    # Per‑class breakdown (approx by prefix)
    print("\n=== Per-class breakdown (approx) ===")
    prefixes = ["Base", "Homograph", "HexIP", "PercentIP", "Shortener", "OpenRedirect",
                "BenignWord", "LeetSpeak", "ZeroWidth", "CharSwap", "HTMLEntity", "Base64Body",
                "Combo1", "Combo2", "Combo3", "Combo4", "Combo5", "Combo6", "Combo7", "Combo8"]
    for pref in prefixes:
        subset = [(d, r) for d, r in adv_samples if d.startswith(pref)]
        if not subset:
            continue
        o = sum(1 for _, r in subset if detect_original(r))
        h = sum(1 for _, r in subset if detect_hardened(r))
        rate_o = o / len(subset) * 100
        rate_h = h / len(subset) * 100
        print(f"{pref:12} | Orig: {rate_o:5.1f}% | Hard: {rate_h:5.1f}% | Delta: {rate_h-rate_o:+5.1f}")

    # Legitimate control evaluation
    print("\n=== Legitimate Control Evaluation ===")
    total_legit = len(LEGIT_CONTROLS)
    legit_fp = 0
    legit_fp_list = []
    for idx, raw in enumerate(LEGIT_CONTROLS):
        pred = detect_hardened(raw)  # we consider hardened path for FP
        if pred:
            legit_fp += 1
            legit_fp_list.append(f"Control#{idx+1}")
    fp_rate = legit_fp / total_legit * 100 if total_legit else 0.0
    print(f"Legitimate controls : {total_legit}")
    print(f"False positives    : {legit_fp}")
    print(f"False-positive rate: {fp_rate:.1f}%")
    if legit_fp_list:
        print("False positive controls:", ", ".join(legit_fp_list))

if __name__ == "__main__":
    main()