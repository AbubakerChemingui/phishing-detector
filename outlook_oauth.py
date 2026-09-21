"""
outlook_oauth.py - Microsoft OAuth2 login for Outlook IMAP.

Why this file exists: Microsoft disabled password login (basic auth) for
Outlook IMAP, so EMAIL_PASSWORD cannot work there. Instead we obtain an
OAuth2 access token (device-code flow, browser sign-in once) and present it
via IMAP XOAUTH2. Gmail is unaffected and keeps using its app password.

One-time Azure setup (in your browser, ~10 min):
  1. https://portal.azure.com -> sign in with your Outlook account
  2. Microsoft Entra ID -> App registrations -> New registration
  3. Name: phishing-firewall ; Supported account types:
     "Personal Microsoft accounts only" ; Register (no redirect URI needed)
  4. Overview page -> copy Application (client) ID.
     Tenant: use "consumers" (no need to copy anything).
  5. API permissions -> Add a permission -> Office 365 Exchange Online ->
     Delegated permissions -> check IMAP.AccessAsUser.All -> Add permissions.
     (Personal accounts consent at sign-in; no admin needed.)
  6. Authentication (left menu) -> Advanced settings ->
     "Allow public client flows" -> Yes -> Save.  (Required for device login.)

Then set env vars and run `python outlook_oauth.py` once to sign in.
The refresh token is cached in .outlook_token_cache.bin (gitignored);
later runs reuse it silently until it expires (~90 days of inactivity).
"""
import os
import sys

try:
    import msal
except ImportError:
    msal = None

CLIENT_ID = os.environ.get("OUTLOOK_CLIENT_ID", "")
TENANT_ID = os.environ.get("OUTLOOK_TENANT_ID", "consumers")
AUTHORITY = "https://login.microsoftonline.com/%s" % TENANT_ID
SCOPES = ["https://outlook.office365.com/IMAP.AccessAsUser.All"]
CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           ".outlook_token_cache.bin")


def _load_app():
    if msal is None:
        raise RuntimeError("the 'msal' package is not installed "
                           "(run: python -m pip install msal)")
    if not CLIENT_ID:
        raise RuntimeError("set OUTLOOK_CLIENT_ID first (Azure app registration)")
    cache = msal.SerializableTokenCache()
    if os.path.exists(CACHE_FILE):
        cache.deserialize(open(CACHE_FILE, "r").read())
    app = msal.PublicClientApplication(CLIENT_ID, authority=AUTHORITY,
                                       token_cache=cache)
    return app, cache


def get_access_token():
    """Return a valid access token, signing in via browser on first run."""
    app, cache = _load_app()
    accounts = app.get_accounts()
    result = None
    if accounts:
        result = app.acquire_token_silent(SCOPES, account=accounts[0])
    if not result:
        flow = app.initiate_device_flow(scopes=SCOPES)
        if "user_code" not in flow:
            raise RuntimeError("could not start device login: %s" % flow)
        print("OUTLOOK SIGN-IN (one time):")
        print("  1. open in your browser: %s" % flow["verification_uri"])
        print("  2. enter this code: %s" % flow["user_code"])
        result = app.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        raise RuntimeError("sign-in failed: %s"
                           % result.get("error_description", result))
    with open(CACHE_FILE, "w") as fh:
        fh.write(cache.serialize())
    try:
        os.chmod(CACHE_FILE, 0o600)
    except Exception:
        pass
    return result["access_token"]


def build_xoauth2_response(username, access_token):
    """Bytes response for imaplib.IMAP4.authenticate('XOAUTH2', ...).

    imaplib base64-encodes whatever this returns, so it MUST be bytes.
    """
    return ("user=%s\x01auth=Bearer %s\x01\x01"
            % (username, access_token)).encode("utf-8")


if __name__ == "__main__":
    token = get_access_token()
    print("OK - signed in. Token acquired (%d chars), cached for silent reuse."
          % len(token))
