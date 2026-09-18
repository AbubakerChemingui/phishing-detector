"""
url_analysis.py – URL feature extraction for phishing detection.
Provides lightweight, rule‑based URL risk scoring that can be added
as an additive signal to the existing Random Forest model.
"""

import re
import urllib.parse
import socket
import idna
from typing import List, Tuple, Dict

# ----------------------------------------------------------------------
# Known malicious / suspicious patterns (can be extended)
# ----------------------------------------------------------------------
SUSPICIOUS_TLDS = {
    'xyz', 'top', 'club', 'info', 'ru', 'cn', 'tk', 'ga', 'cf', 'gq',
    'ml', 'men', 'pw', 'cc', 'biz', 'ws', 'zip', 'mov', 'review',
    'country', 'science', 'work'
}
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'bit.do', 'shorte.st', 'cutt.ly', 'rebrand.ly',
    'v.gd', 'tr.im', 'linktr.ee'
}
OPEN_REDIRECTORS = {
    'google.com/url', 'facebook.com/l.php', 'twitter.com/i/url',
    'linkedin.com/redir', 'reddit.com/r/', 'yahoo.com/r/',
    'bing.com/r', 'duckduckgo.com/l/?uddg='
}
# Characters often used to obfuscate in URLs
OBFUSCATION_CHARS = set('%@')  # percent encoding, @ userinfo trick

# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------
def _decode_punycode(host: str) -> str:
    """Return ASCII representation if host is IDN, else original."""
    try:
        return idna.encode(host).decode('ascii')
    except idna.IDNAError:
        return host

def _is_ip_address(host: str) -> bool:
    """Check if host string is an IPv4 or IPv6 address."""
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, host)
            return True
        except OSError:
            return False

def _extract_urls(raw_text: str) -> List[str]:
    """
    Very tolerant URL extraction: finds strings that look like
    http/https/ftp/mailto followed by non‑space characters,
    also catches www. prefixed strings.
    """
    # Pattern catches http(s)://..., ftp://..., mailto:, and www.
    url_pattern = re.compile(
        r'(?:(?:https?|ftp|mailto):\/\/|www\.)[^\s\<\>\"\'\)\]\}]+',
        re.IGNORECASE
    )
    return url_pattern.findall(raw_text)

def _normalize_url(url: str) -> str:
    """Lowercase, trim trailing punctuation, and decode percent‑encoding."""
    url = url.strip().lower()
    # Strip trailing punctuation that is not part of URL
    url = url.rstrip('.,:;!?\'"\)] }')
    try:
        return urllib.parse.unquote(url)
    except Exception:
        return url

def _has_suspicious_tld(host: str) -> bool:
    """Return True if host ends with a suspicious TLD."""
    # Extract last label after final dot
    if '.' not in host:
        return False
    tld = host.split('.')[-1]
    return tld in SUSPICIOUS_TLDS

def _is_shortener(host: str) -> bool:
    return any(short in host for short in URL_SHORTENERS)

def _is_open_redirect(host_path: str) -> bool:
    host_path = host_path.lower()
    for redir in OPEN_REDIRECTORS:
        if redir in host_path:
            return True
    return False

def _contains_obfuscation(url: str) -> bool:
    """Detect simple obfuscation tricks."""
    # Percent encoded characters
    if '%' in url:
        return True
    # @ userinfo trick (e.g., http:// legit@evil.com/path)
    if '@' in url and url.count('@') > 1:
        return True
    # Hex/decimal IP encoded (detected separately)
    return False

def analyze_url_features(raw_text: str) -> Dict[str, float]:
    """
    Analyse all URLs in raw_text and return a dict of binary flags
    plus a combined risk score (0‑1).
    Flags:
        has_ip, suspicious_tld, shortener, open_redirect,
        obfuscated, homograph, percent_encoded, hex_ip
    """
    urls = _extract_urls(raw_text)
    if not urls:
        return {
            'url_count': 0,
            'has_ip': 0.0,
            'suspicious_tld': 0.0,
            'shortener': 0.0,
            'open_redirect': 0.0,
            'obfuscated': 0.0,
            'homograph': 0.0,
            'percent_encoded': 0.0,
            'hex_ip': 0.0,
            'url_risk': 0.0
        }

    # Counters
    n_ip = n_susp = n_short = n_open = n_obf = n_homo = n_pct = n_hexip = 0

    for raw_u in urls:
        u = _normalize_url(raw_u)
        # Split scheme://host/path
        try:
            parsed = urllib.parse.urlparse(u if '://' in u else 'http://' + u)
        except Exception:
            continue
        host = parsed.hostname or ''
        path = parsed.path or ''
        full_host_path = host + path

        # IP‑address host
        if host and _is_ip_address(host):
            n_ip += 1

        # Suspicious TLD
        if host and _has_suspicious_tld(host):
            n_susp += 1

        # URL shortener
        if host and _is_shortener(host):
            n_short += 1

        # Open redirector
        if _is_open_redirect(full_host_path):
            n_open += 1

        # Percent encoding
        if '%' in raw_u:
            n_pct += 1

        # Obfuscation (hex/decimal IP encoded in host part)
        # Detect patterns like %31%32%2e%33%34... or decimal IP without dots
        if re.search(r'%(?:[0-9A-Fa-f]{2}){2,}', raw_u) or \
           re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', host) is None and \
           re.search(r'\d{7,15}', host):
            # Rough heuristic: long digit string without dots could be decimal IP
            n_hexip += 1

        # Homograph detection – compare ASCII skeleton
        if host:
            ascii_host = _decode_punycode(host)
            if ascii_host != host and ascii_host.isascii():
                n_homo += 1

        # General obfuscation flag (percent, @ userinfo, etc.)
        if _contains_obfuscation(raw_u):
            n_obf += 1

    total = len(urls)
    # Simple weighted risk (weights can be tuned)
    risk = (
        0.30 * (n_ip / total) +
        0.20 * (n_susp / total) +
        0.15 * (n_short / total) +
        0.15 * (n_open / total) +
        0.10 * (n_pct / total) +
        0.05 * (n_homo / total) +
        0.05 * (n_obf / total)
    )
    risk = min(risk, 1.0)

    return {
        'url_count': float(total),
        'has_ip': float(n_ip) / total,
        'suspicious_tld': float(n_susp) / total,
        'shortener': float(n_short) / total,
        'open_redirect': float(n_open) / total,
        'obfuscated': float(n_obf) / total,
        'homograph': float(n_homo) / total,
        'percent_encoded': float(n_pct) / total,
        'hex_ip': float(n_hexip) / total,
        'url_risk': risk
    }

# ----------------------------------------------------------------------
# Simple interface for external callers
# ----------------------------------------------------------------------
def get_url_risk(raw_text: str) -> float:
    """Convenience wrapper returning only the combined risk score."""
    return analyze_url_features(raw_text)['url_risk']