"""PhishGuard: explainable, rule-based phishing URL risk analysis.

This module analyzes URL text only. It never opens, fetches, or executes a URL.
"""
from urllib.parse import urlsplit
import ipaddress
import re

SUSPICIOUS_TERMS = {
    "login", "verify", "account", "password", "update", "secure",
    "banking", "signin", "confirm", "wallet", "payment",
}
SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly",
    "buff.ly", "cutt.ly", "rb.gy",
}


def normalize_url(raw_url: str) -> str:
    """Trim whitespace and add https:// when no scheme is supplied."""
    if not isinstance(raw_url, str):
        raise TypeError("URL must be provided as text.")
    value = raw_url.strip()
    if not value:
        raise ValueError("Enter a URL to analyze.")
    # Do not permit control characters that can make a URL ambiguous.
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("URL contains unsupported control characters.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value
    return value


def analyze_url(raw_url: str) -> dict:
    """Return a heuristic score, risk label, and reasons for the given URL text."""
    normalized = normalize_url(raw_url)
    parsed = urlsplit(normalized)

    if parsed.scheme.lower() not in {"http", "https"}:
        return {
            "input": raw_url,
            "normalized_url": normalized,
            "score": 100,
            "risk": "High",
            "reasons": ["URL uses a non-HTTP(S) scheme."],
            "host": parsed.hostname or "",
        }

    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError("Could not identify a hostname in this URL.")

    score = 0
    reasons = []

    def add(points: int, reason: str):
        nonlocal score
        score += points
        reasons.append(f"+{points}: {reason}")

    if "@" in parsed.netloc:
        add(25, "The URL authority contains '@', which can obscure the actual host.")
    try:
        ipaddress.ip_address(host)
        add(25, "The hostname is an IP address rather than a domain name.")
    except ValueError:
        pass

    if len(normalized) > 100:
        add(15, "The URL is unusually long (over 100 characters).")

    # Count labels before the final two labels as a simple, imperfect heuristic.
    labels = [label for label in host.split(".") if label]
    if len(labels) >= 5:
        add(15, "The hostname has many subdomain labels.")

    lower_url = normalized.lower()
    found_terms = sorted(term for term in SUSPICIOUS_TERMS if term in lower_url)
    if found_terms:
        add(10, "Contains security-sensitive terms: " + ", ".join(found_terms) + ".")

    if host in SHORTENER_HOSTS:
        add(15, "Uses a known URL-shortening service that hides the destination.")

    if parsed.scheme.lower() == "http":
        add(5, "Uses HTTP rather than encrypted HTTPS.")

    score = min(score, 100)
    if score >= 50:
        risk = "High"
    elif score >= 25:
        risk = "Medium"
    else:
        risk = "Low"

    if not reasons:
        reasons.append("No configured warning patterns were detected.")

    return {
        "input": raw_url,
        "normalized_url": normalized,
        "score": score,
        "risk": risk,
        "reasons": reasons,
        "host": host,
    }
