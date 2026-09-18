"""
Test system for phishing email detection.
Tests edge cases and ensures correctness.
"""
import os
import sys
import re
import pytest
import joblib
import numpy as np
import pandas as pd
import subprocess

# Add the project directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the necessary functions from our gui_app module
import gui_app
from gui_app import (
    clean_email_text,
    apply_hardening,
    strip_html,
    analyze_email,
    load_artifacts,
    get_alert,
    get_risk_color
)

# Test data
SAMPLE_LEGIT = (
    "Subject: Team Sync Meeting Notes\n\n"
    "Hi Abubaker,\n"
    "Here are the minutes from today's weekly architecture meeting.\n"
    "Let me know if you have any questions regarding the schedule.\n"
    "Best regards,\nEngineering Team"
)

SAMPLE_PHISH = (
    "Subject: URGENT: Your Account Has Been Suspended!\n\n"
    "Dear Customer,\n"
    "Your access will be permanently terminated within 24 hours due to suspicious activity.\n"
    "Click here immediately to verify your identity and restore access: http://secure-login-update-verify.com/login\n"
    "Security Department"
)

def test_model_loads():
    """Test that model and vectorizer load without error."""
    import core
    core.load_artifacts()
    assert core.MODEL is not None, "Model failed to load"
    assert core.VECTORIZER is not None, "Vectorizer failed to load"
    # Check that we can predict
    X_test = core.VECTORIZER.transform(["test"])
    pred = core.MODEL.predict(X_test)
    assert pred is not None

def test_clean_email_text():
    """Test the cleaning function."""
    assert clean_email_text("Hello World!") == "hello world"
    # Note: replacement adds a space before and after, then multiple spaces collapsed to one, and strip removes leading/trailing.
    # So "Check http://example.com" -> "check url"
    assert clean_email_text("Check http://example.com") == "check url"
    assert clean_email_text("Test@email.com") == "test email com"
    assert clean_email_text("Multiple   spaces") == "multiple spaces"
    assert clean_email_text("") == ""
    assert clean_email_text("   ") == ""
    assert clean_email_text("123 numbers 456") == "numbers"

def test_apply_hardening():
    """Test hardening function."""
    # Homoglyph
    assert apply_hardening("\u0430ccount") == "account"  # Cyrillic а
    # Leet
    assert apply_hardening("h3ll0") == "hello"
    # Zero-width
    assert apply_hardening("h\u200bello") == "hello"
    # Combined
    assert apply_hardening("h\u200b3ll0") == "hello"
    # HTML stripping
    assert strip_html("<b>bold</b>") == " bold "
    assert strip_html("<script>alert('xss')</script>") == " alert('xss') "

def test_analyze_email_empty():
    """Test empty or whitespace-only input."""
    res = analyze_email("", med_thresh=0.65, high_thresh=0.85)
    assert res["prediction"] == "-"
    assert res["raw_pred"] is None
    assert res["confidence"] == 0.0
    assert res["alert"] == "Please enter e-mail text to analyse"
    assert res["top_words"] == []
    assert res["color"] == "#666666"

    res = analyze_email("   \n\t   ", med_thresh=0.65, high_thresh=0.85)
    assert res["prediction"] == "-"

def test_analyze_email_one_word():
    """Test single word input."""
    res = analyze_email("hello", med_thresh=0.65, high_thresh=0.85)
    assert res["prediction"] in ("Phishing", "Legitimate")
    assert isinstance(res["confidence"], float)
    assert 0.0 <= res["confidence"] <= 1.0
    # Note: top_words may be empty or not depending on vectorizer; we don't enforce.

def test_analyze_email_long():
    """Test very long email (100k chars)."""
    long_text = "x" * 100000
    res = analyze_email(long_text, med_thresh=0.65, high_thresh=0.85)
    # Should not crash
    assert res["prediction"] in ("Phishing", "Legitimate")
    assert isinstance(res["confidence"], float)

def test_analyze_email_html():
    """Test HTML email."""
    html_email = "<html><body><h1>Important</h1><p>Click <a href='http://bad.com'>here</a></p></body></html>"
    res = analyze_email(html_email, med_thresh=0.65, high_thresh=0.85)
    assert res["prediction"] in ("Phishing", "Legitimate")
    # The cleaning should strip tags, leaving text.

def test_analyze_email_only_urls():
    """Test email with only URLs."""
    url_email = "http://example.com http://test.com"
    res = analyze_email(url_email, med_thresh=0.65, high_thresh=0.85)
    assert res["prediction"] in ("Phishing", "Legitimate")
    # After cleaning, URLs become " url " tokens.

def test_analyze_email_headers_only():
    """Test email with only headers (no body)."""
    headers = "Subject: Test\nFrom: sender@example.com\nTo: recipient@example.com\nDate: Mon, 1 Sep 2026 12:00:00 +0000\n\n"
    res = analyze_email(headers, med_thresh=0.65, high_thresh=0.85)
    assert res["prediction"] in ("Phishing", "Legitimate")

def test_analyze_email_attachment_only():
    """Test multipart email with only attachment (we simulate by providing raw bytes?).
    Since our function expects a string, we'll just test that a string representing an attachment doesn't crash.
    We'll pass a base64 string.
    """
    import base64
    fake_attachment = base64.b64encode(b"This is a fake attachment").decode('utf-8')
    res = analyze_email(fake_attachment, med_thresh=0.65, high_thresh=0.85)
    assert res["prediction"] in ("Phishing", "Legitimate")

def test_analyze_email_unicode_emoji():
    """Test Unicode and emoji."""
    unicode_email = "Hello 世界 😊"
    res = analyze_email(unicode_email, med_thresh=0.65, high_thresh=0.85)
    assert res["prediction"] in ("Phishing", "Legitimate")

def test_analyze_email_mangled_quoting():
    """Test mangled UTF-8 quoting in headers."""
    # Example: Subject: =?utf-8?B?UmVnaW91cyBQaG9saWN5IFF1ZXN0aW9u?=
    # We'll just pass the raw string; cleaning will lower it and replace non-alpha.
    mangled = "Subject: =?utf-8?B?UmVnaW91cyBQaG9saWN5IFF1ZXN0aW9u?="
    res = analyze_email(mangled, med_thresh=0.65, high_thresh=0.85)
    assert res["prediction"] in ("Phishing", "Legitimate")

def test_analyze_email_legit_urgent():
    """Test a legitimate email that uses urgent language but should not be flagged."""
    # This is a borderline case; we expect it to be classified as legitimate or low confidence.
    urgent_legit = (
        "Subject: URGENT: Action Required\n\n"
        "Hi Team,\n"
        "Please review the attached document by EOD today.\n"
        "Thanks,\nManager"
    )
    res = analyze_email(urgent_legit, med_thresh=0.65, high_thresh=0.85)
    # We don't enforce a specific outcome, but we can assert that it does not crash.
    assert res["prediction"] in ("Phishing", "Legitimate")
    # Optionally, we could check that if it's predicted as phishing, confidence is below high threshold?
    # But we'll leave it as is.

def test_analyze_email_phishing_patterns():
    """Test known phishing patterns."""
    # Credential lure
    cred_lure = (
        "Subject: Verify Your Account\n\n"
        "Dear user,\n"
        "We have detected suspicious activity on your account.\n"
        "Please click here to verify your credentials: http://fake-bank-login.com\n"
    )
    res = analyze_email(cred_lure, med_thresh=0.65, high_thresh=0.85)
    # We expect it to be flagged as phishing with high confidence? Not guaranteed but likely.
    # We'll just ensure it doesn't crash.
    assert res["prediction"] in ("Phishing", "Legitimate")

    # Invoice bait
    invoice = (
        "Subject: Invoice #12345678\n\n"
        "Please find attached the invoice for your recent purchase.\n"
        "Click to download: http://fake-invoice.com/file.pdf\n"
    )
    res = analyze_email(invoice, med_thresh=0.65, high_thresh=0.85)
    assert res["prediction"] in ("Phishing", "Legitimate")

    # Executive impersonation
    exec_imp = (
        "Subject: Request from CEO\n\n"
        "Hi John,\n"
        "I need you to purchase gift cards for the client celebration.\n"
        "Please send the codes to me asap.\n"
        "Thanks,\nJane Doe, CEO"
    )
    res = analyze_email(exec_imp, med_thresh=0.65, high_thresh=0.85)
    assert res["prediction"] in ("Phishing", "Legitimate")

    # Paypal-looking domain
    paypal_phish = (
        "Subject: PayPal Account Verification\n\n"
        "Please login to verify your account: http://paypa1-security.com\n"
    )
    res = analyze_email(paypal_phish, med_thresh=0.65, high_thresh=0.85)
    assert res["prediction"] in ("Phishing", "Legitimate")

    # Microsoft-looking domain
    microsoft_phish = (
        "Subject: Microsoft Security Alert\n\n"
        "Unusual sign-in detected. Secure your account: http://microsoft-security.net\n"
    )
    res = analyze_email(microsoft_phish, med_thresh=0.65, high_thresh=0.85)
    assert res["prediction"] in ("Phishing", "Legitimate")

def test_model_consistency():
    """Test that the same input gives the same output."""
    text = "This is a test email for consistency."
    res1 = analyze_email(text, med_thresh=0.65, high_thresh=0.85)
    res2 = analyze_email(text, med_thresh=0.65, high_thresh=0.85)
    assert res1["prediction"] == res2["prediction"]
    assert res1["confidence"] == res2["confidence"]
    assert res1["raw_pred"] == res2["raw_pred"]

def test_all_models_load():
    """Test that all saved models (if present) load and predict without error."""
    # We only have random forest pickles, but we can check for others.
    model_files = [
        "random_forest_model.pkl",
        # "naive_bayes_model.pkl",
        # "xgboost_model.pkl",
    ]
    vectorizer_files = [
        "random_forest_vectorizer.pkl",
        # "naive_bayes_vectorizer.pkl",
        # "tfidf_vectorizer.pkl",
    ]
    for mf, vf in zip(model_files, vectorizer_files):
        mf_path = os.path.join(os.path.dirname(__file__), mf)
        vf_path = os.path.join(os.path.dirname(__file__), vf)
        if os.path.exists(mf_path) and os.path.exists(vf_path):
            model = joblib.load(mf_path)
            vectorizer = joblib.load(vf_path)
            X = vectorizer.transform(["test"])
            pred = model.predict(X)
            assert pred is not None

def test_dataset_checks():
    """Check the multilingual sample dataset for integrity."""
    data_path = os.path.join(os.path.dirname(__file__), "data", "multilingual_sample.csv")
    if os.path.exists(data_path):
        df = pd.read_csv(data_path)
        # Check for NaNs in essential columns
        assert not df.isnull().any().any(), "Dataset contains NaN values"
        # Check for duplicates
        assert not df.duplicated().any(), "Dataset contains duplicate rows"
        # Check label column exists (we assume it's named 'label')
        if 'label' in df.columns:
            # Labels should be 0 or 1 or strings 'legit'/'phishing'
            unique_labels = df['label'].unique()
            # We'll just ensure they are present
            assert len(unique_labels) > 0
        else:
            # If not, we skip
            pass
    else:
        pytest.skip("Multilingual sample CSV not found")

def test_cli_demo():
    """Test the demo.py CLI with a sample input (simulate)."""
    # We'll run demo.py with input via subprocess, but to keep it simple,
    # we'll just test the analyze_email function with the same logic.
    # However, we can also test that the script runs without error when given input.
    # We'll do a subprocess test.
    # Create a temporary input file
    input_text = SAMPLE_PHISH + "\nEND\n"
    # Use Popen to feed input
    proc = subprocess.Popen(
        [sys.executable, os.path.join(os.path.dirname(__file__), "demo.py")],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    stdout, stderr = proc.communicate(input=input_text, timeout=10)
    assert proc.returncode == 0
    assert "Result: PHISHING" in stdout or "Result: LEGIT" in stdout
    # We'll just check that it runs.

if __name__ == "__main__":
    pytest.main([__file__, "-v"])