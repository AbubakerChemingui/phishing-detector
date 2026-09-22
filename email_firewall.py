"""
email firewall - phishing auto-detection
connects to an imap inbox, scans unread emails, and auto-moves phishing emails to spam.
"""

import os
import sys
import time
import argparse
import imaplib
import email
from email.header import decode_header
import html
import re
import joblib

# Console may be cp1252 (cannot print e.g. emoji filenames): never crash on output.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# Import core logic for hardened detection
import core
import url_analysis
# configuration from env vars with defaults
core.load_artifacts()
EMAIL_ADDRESS = os.environ.get("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD")

# Set to True (e.g. via --harden) to normalize homoglyph/leet/zero-width tricks before detection
HARDEN_FIRST = False

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "firewall.log")


def log_line(text=""):
    """Print to the terminal AND append to firewall.log (audit trail).

    The log survives scrolling/closed terminals and records every verdict
    and action with a timestamp. Never raises: logging must not break scans.
    """
    print(text)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {text}\n")
    except Exception:
        pass
PROVIDER = os.environ.get("EMAIL_PROVIDER") or os.environ.get("PROVIDER") or "gmail"
PHISHING_CONFIDENCE_THRESHOLD = 0.65
_env_threshold = os.environ.get("PHISHING_CONFIDENCE_THRESHOLD")
if _env_threshold is not None:
    try:
        PHISHING_CONFIDENCE_THRESHOLD = float(_env_threshold)
    except ValueError:
        print(f"warning: PHISHING_CONFIDENCE_THRESHOLD='{_env_threshold}' is not a number, using default 0.65")

PROVIDER_SETTINGS = {
    "gmail": {"imap_server": "imap.gmail.com", "spam_folder": '[Gmail]/Spam'},
    "outlook": {"imap_server": "outlook.office365.com", "spam_folder": 'Junk'},
}

# model loading
model_path = os.path.join(os.path.dirname(__file__), "random_forest_model.pkl")
vectorizer_path = os.path.join(os.path.dirname(__file__), "random_forest_vectorizer.pkl")

try:
    model = joblib.load(model_path)
    vectorizer = joblib.load(vectorizer_path)
except Exception as e:
    model = None
    vectorizer = None


def diagnose_email(raw, headers=""):
    """Print the full decision breakdown for one email: model probability,
    URL-risk flags, auth-header checks, final verdict, top words. Use this to
    find out WHY a legitimate email was flagged (or a phish missed)."""
    text = core.apply_hardening(raw) if HARDEN_FIRST else raw
    cleaned = core.clean_email_text(text)
    X = core.VECTORIZER.transform([cleaned])
    proba = float(core.MODEL.predict_proba(X)[0][1])
    scope = raw if not headers else raw + "\n" + headers
    auth_scope = headers if headers else raw
    feats = url_analysis.analyze_url_features(scope)
    auth = core.check_auth_headers(auth_scope)
    authp = core.check_auth_pass(auth_scope)
    result = core.analyze_email(raw, med_thresh=0.65, high_thresh=0.85,
                                harden_first=HARDEN_FIRST, headers=headers)
    print(f"  model P(phishing) = {proba:.3f} (cleaned chars={len(cleaned)})")
    log_line(f"  url_risk = {feats['url_risk']:.2f} "
             f"(urls={feats['url_count']:.0f} ip={feats['has_ip']:.0f} "
             f"tld={feats['suspicious_tld']:.0f} short={feats['shortener']:.0f} "
             f"redirect={feats['open_redirect']:.0f} obf={feats['obfuscated']:.0f} "
             f"homo={feats['homograph']:.0f} pct={feats['percent_encoded']:.0f} "
             f"hexip={feats['hex_ip']:.0f})")
    log_line(f"  auth_fail = {auth}   auth_pass = {authp}")
    log_line(f"  verdict = {result['prediction']} ({result['confidence_str']})")
    print(f"  top_words = {', '.join(w for w, _s in result['top_words'][:8])}")


def scan_folder(folder_path, verbose=False):
    """
    Dry-run mode: scan all .eml and .txt files in folder_path,
    print filename and prediction (Phishing/Legitimate) using hardened core.
    """
    if not os.path.isdir(folder_path):
        log_line(f"error: {folder_path} is not a directory")
        return
    files = [f for f in os.listdir(folder_path) if f.lower().endswith(('.eml', '.txt'))]
    if not files:
        log_line("No .eml or .txt files found in folder.")
        return
    log_line(f"Scanning {len(files)} files in {folder_path}")
    for fname in files:
        path = os.path.join(folder_path, fname)
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                raw = fh.read()
        except Exception as e:
            print(f"{fname}: error reading file - {e}")
            continue
        # Parse like the live path: content (subject+body) for the model,
        # headers for URL/auth signals. Plain .txt notes fall back to raw text.
        msg = email.message_from_string(raw)
        subject = decode_mime_words(msg.get("Subject", ""))
        body = get_email_body(msg)
        if subject.strip() or body.strip():
            text = f"{subject} {body}"
            headers_text = "\n".join(f"{k}: {v}" for k, v in msg.items())
        else:
            text, headers_text = raw, ""
        # Use hardened analysis
        result = core.analyze_email(text, med_thresh=0.65, high_thresh=0.85,
                                    harden_first=HARDEN_FIRST, headers=headers_text)
        verdict = result["prediction"]
        conf = result["confidence_str"]
        log_line(f"{fname}: {verdict} ({conf})")
        if verbose:
            diagnose_email(text, headers_text)


def classify_email(subject, body, headers=""):
    """
    Classify an email using the hardened core logic (URL + header checks + model).
    headers: raw header block (enables SPF/DKIM/DMARC pass/fail signals).
    Returns (prediction_label, confidence_str, confidence_float) where
    prediction_label is "Phishing" or "Legitimate".
    """
    if model is None or vectorizer is None:
        raise RuntimeError("model files could not be loaded")
    full_text = f"{subject} {body}"
    result = core.analyze_email(full_text, med_thresh=0.65, high_thresh=0.85,
                                harden_first=HARDEN_FIRST, headers=headers)
    return result["prediction"], result["confidence_str"], float(result["confidence"])


def strip_html(html_text):
    # strip html tags and decode html entities
    text = re.sub(r'<[^>]+>', ' ', html_text)
    text = html.unescape(text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def decode_mime_words(s):
    if not s:
        return ""
    decoded = decode_header(s)
    parts = []
    for text, enc in decoded:
        if isinstance(text, bytes):
            parts.append(text.decode(enc or "utf-8", errors="ignore"))
        else:
            parts.append(str(text))
    return "".join(parts)


def decode_payload(part):
    # decode body using the charset the email declares, utf-8 as fallback
    charset = part.get_content_charset() or "utf-8"
    payload = part.get_payload(decode=True)
    if not payload:
        return ""
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, ValueError):
        # unknown charset label, fall back to utf-8
        return payload.decode("utf-8", errors="replace")


def get_email_body(msg):
    # try plain text first, fallback to html if no plain text
    plain_body = ""
    html_body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))
            if "attachment" in content_disposition:
                continue
            if content_type == "text/plain" and not plain_body:
                try:
                    plain_body = decode_payload(part)
                except Exception:
                    pass
            elif content_type == "text/html" and not html_body:
                try:
                    html_body = decode_payload(part)
                except Exception:
                    pass
    else:
        content_type = msg.get_content_type()
        try:
            text = decode_payload(msg)
            if content_type == "text/html":
                html_body = text
            else:
                plain_body = text
        except Exception:
            pass
    if plain_body and plain_body.strip():
        return plain_body.strip()
    elif html_body and html_body.strip():
        return strip_html(html_body)
    return ""


def run_scan():
    # fail fast instead of scanning a whole inbox with no model
    if model is None or vectorizer is None:
        print("error: could not load random_forest_model.pkl / random_forest_vectorizer.pkl")
        return False

    # one full scan cycle. returns True if it completed, False on connection-level failure
    provider_key = PROVIDER.lower().strip()
    if provider_key not in PROVIDER_SETTINGS:
        print(f"warning: unknown provider '{PROVIDER}'. defaulting to gmail settings.")
        provider_key = "gmail"

    settings = PROVIDER_SETTINGS[provider_key]
    spam_folder = settings["spam_folder"]

    print(f"connecting to {settings['imap_server']} for account '{EMAIL_ADDRESS}'...")
    try:
        mail = imaplib.IMAP4_SSL(settings["imap_server"])
        if provider_key == "outlook":
            # Microsoft disabled password login for Outlook IMAP:
            # sign in with OAuth2 and authenticate via XOAUTH2 instead.
            try:
                from outlook_oauth import build_xoauth2_response, get_access_token
            except ImportError:
                print("error: outlook sign-in needs the 'msal' package (python -m pip install msal)")
                return False
            try:
                token = get_access_token()
            except RuntimeError as e:
                print(f"outlook sign-in failed: {e}")
                return False
            mail.authenticate("XOAUTH2",
                              lambda _resp: build_xoauth2_response(EMAIL_ADDRESS, token))
        else:
            mail.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    except Exception as e:
        print("login/connection failed. please verify credentials and app password settings.")
        print(f"details: {e}")
        return False

    status, _ = mail.select("INBOX")
    if status != "OK":
        print("error: could not select INBOX.")
        mail.logout()
        return False

    status, message_numbers = mail.search(None, "UNSEEN")
    if status != "OK":
        print("error: could not search unread emails in INBOX.")
        mail.logout()
        return False

    ids = message_numbers[0].split()
    total_emails = len(ids)
    log_line(f"found {total_emails} unread email(s) in INBOX.")

    if total_emails == 0:
        mail.logout()
        log_line("scan complete. no unread emails to process.")
        return True

    flagged_count = 0
    kept_count = 0
    error_count = 0
    spam_move_failed = False

    for idx, num in enumerate(ids, start=1):
        try:
            status, msg_data = mail.fetch(num, "(RFC822)")
            if status != "OK" or not msg_data or not msg_data[0]:
                email_id_str = num.decode() if isinstance(num, bytes) else str(num)
                log_line(f"[{idx}/{total_emails}] error: failed to fetch email ID {email_id_str}")
                error_count += 1
                continue

            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)

            subject = decode_mime_words(msg.get("Subject", "(no subject)"))
            sender = decode_mime_words(msg.get("From", "(unknown sender)"))
            body = get_email_body(msg)
            headers_text = "\n".join(f"{k}: {v}" for k, v in msg.items())

            prediction, confidence, conf_value = classify_email(subject, body, headers_text)

            log_line(f"[{idx}/{total_emails}] From: {sender}")
            log_line(f"  Subject: {subject}")
            log_line(f"  Result:  {prediction} (confidence: {confidence})")

            # Move only high-confidence phishing to Spam: the label comes from the
            # hardened core, and PHISHING_CONFIDENCE_THRESHOLD (default 0.65, set
            # via env) keeps marginal calls in the inbox for human review.
            # Measured trade-off on 16,438 emails: 0.65 halves the FPR
            # (1.26% -> 0.53%) for ~3pp of recall (see MODEL_AUDIT.md).
            is_phishing = (prediction == "Phishing"
                           and conf_value >= PHISHING_CONFIDENCE_THRESHOLD)
            if prediction == "Phishing" and not is_phishing:
                kept_count += 1
                log_line(f"  Action:  KEPT in INBOX (below move threshold "
                         f"{PHISHING_CONFIDENCE_THRESHOLD:.2f})")
            elif is_phishing:
                target_folder = format_folder_name(spam_folder)
                copy_status, copy_data = mail.copy(num, target_folder)
                if copy_status == "OK":
                    mail.store(num, "+FLAGS", "\\Deleted")
                    flagged_count += 1
                    log_line(f"  Action:  MOVED to spam folder ({spam_folder})")
                else:
                    log_line(f"  Action:  FAILED to move to spam folder ({spam_folder}). IMAP response: {copy_data}")
                    if not spam_move_failed:
                        spam_move_failed = True
                        log_line("")
                        log_line("available folders on your account:")
                        folders = list_available_folders(mail)
                        for f in folders:
                            log_line(f"  - {f}")
                        log_line("")
                        log_line("please check the spam folder name above and update your folder configuration.")
                        log_line("")
                    kept_count += 1
            else:
                kept_count += 1
                log_line("  Action:  KEPT in INBOX")

        except Exception as e:
            error_count += 1
            email_id_str = num.decode() if isinstance(num, bytes) else str(num)
            log_line(f"[{idx}/{total_emails}] error processing email ID {email_id_str}: {e}")

    try:
        mail.expunge()
    except Exception:
        pass

    try:
        mail.logout()
    except Exception:
        pass

    log_line("=" * 40)
    log_line("SCAN SUMMARY")
    log_line("=" * 40)
    log_line(f"Total checked:      {total_emails}")
    log_line(f"Moved to Spam:      {flagged_count}")
    log_line(f"Kept in INBOX:      {kept_count}")
    log_line(f"Errors encountered: {error_count}")
    log_line("=" * 40)
    return True


def list_available_folders(mail):
    # helper to list available imap folders if folder move fails
    try:
        status, folder_list = mail.list()
        if status == "OK" and folder_list:
            folders = []
            for item in folder_list:
                if isinstance(item, bytes):
                    item = item.decode(errors="ignore")
                folders.append(item)
            return folders
    except Exception as e:
        return [f"error listing folders: {e}"]
    return []


def format_folder_name(folder):
    if folder.startswith('"') and folder.endswith('"'):
        return folder
    if any(c in folder for c in [' ', '/', '[', ']']):
        return f'"{folder}"'
    return folder


def main():
    parser = argparse.ArgumentParser(description="phishing email firewall")
    parser.add_argument("--loop", type=int, default=0, metavar="SECONDS",
                        help="rescan inbox every N seconds instead of running once")
    parser.add_argument("--max-retries", type=int, default=5,
                        help="max consecutive connection failures before giving up in loop mode")
    parser.add_argument("--scan-folder", type=str, default=None,
                        help="dry-run mode: scan all .eml/.txt files in folder and print verdicts")
    parser.add_argument("--harden", action="store_true",
                        help="apply text hardening (homoglyph/leet/zero-width normalization) before detection")
    parser.add_argument("--verbose", action="store_true",
                        help="with --scan-folder: print the full decision breakdown per file")
    args = parser.parse_args()

    if args.harden:
        global HARDEN_FIRST
        HARDEN_FIRST = True

    if args.scan_folder:
        scan_folder(args.scan_folder, verbose=args.verbose)
        return

    # Outlook signs in with OAuth2 (see outlook_oauth.py), so it needs no email password.
    provider_key = (PROVIDER or "gmail").lower().strip()
    needs_password = provider_key != "outlook"
    if not EMAIL_ADDRESS or (needs_password and not EMAIL_PASSWORD):
        print("error: missing credentials. set EMAIL_ADDRESS and EMAIL_PASSWORD environment variables.")
        print("example (windows powershell):")
        print("  $env:EMAIL_ADDRESS=\"your_email@gmail.com\"")
        print("  $env:EMAIL_PASSWORD=\"your_16_char_app_password\"")
        print("  $env:EMAIL_PROVIDER=\"gmail\"")
        sys.exit(1)

    if args.loop <= 0:
        ok = run_scan()
        sys.exit(0 if ok else 1)

    # scheduled mode: reconnect each cycle, back off on failures
    log_line(f"scheduled mode: scanning every {args.loop}s. press ctrl+c to stop.")
    fail_streak = 0
    cycle = 1
    try:
        while True:
            log_line(f"--- scan cycle {cycle} ({time.strftime('%Y-%m-%d %H:%M:%S')}) ---")
            ok = run_scan()
            if ok:
                fail_streak = 0
            else:
                fail_streak += 1
                if fail_streak >= args.max_retries:
                    log_line(f"giving up after {fail_streak} consecutive failures.")
                    sys.exit(1)
            cycle += 1
            time.sleep(args.loop)
    except KeyboardInterrupt:
        log_line("stopped by user.")


if __name__ == "__main__":
    main()