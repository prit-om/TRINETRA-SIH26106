"""
Layer 2 — Local / Deterministic Intelligence

This is the offline half of Layer 2 from the Trinetra architecture:

    LAYER 2 — Intelligence + Correlation
        |
        +-- Local/Det. Intelligence   <- THIS MODULE
        |     - IP sanity rules
        |     - local IOC lists
        |     - cached intelligence
        |     - downloaded feeds
        |     - known campaign data
        |
        +-- External APIs (when available)
              - IP reputation, TOR/VPN, domain reputation, WHOIS/DNS, threat feeds

It runs unconditionally (no network, no API key) and ALWAYS contributes a
signal, so Layer 2 is never fully blind even if VirusTotal/GeoIP APIs are
down. External API results (from url_analysis.py, geolocation.py) are
merged with this module's output in layer2_engine.py.

Design note: keep the local lists here small and centralized — this is
also your "known campaign data" store, and doubles as a real, demoable
artifact for judges ("here is our local threat intelligence cache").
"""

import ipaddress
import re
from datetime import datetime, timezone

# --- Local IOC lists (Indicators of Compromise) ----------------------------
# In production these would be loaded from a downloaded feed file and
# refreshed periodically. For the hackathon MVP, a small curated/demo list
# is enough to prove the mechanism works end-to-end.

LOCAL_MALICIOUS_DOMAINS = {
    "malicious-fake-invoice.net",
    "secure-paypal-verify.com",
    "account-update-microsoft.net",
    "invoice-review-secure.net",
}

LOCAL_MALICIOUS_IPS = {
    "185.220.101.5",   # known Tor exit / abuse-listed range (demo entry)
    "45.155.205.1",
}

KNOWN_CAMPAIGN_SENDER_DOMAINS = {
    # domains previously seen in flagged BEC/phishing campaigns during this
    # engagement — populated over time by the feedback loop (stage 11)
    "fakecompany.net",
}

# Hosting/ASN ranges commonly abused for phishing infrastructure (demo set —
# a real deployment would pull this from a maintained abuse-IP-range feed).
SUSPICIOUS_CIDR_RANGES = [
    "185.220.100.0/22",   # known Tor exit node range
    "45.155.204.0/22",    # known bulletproof-hosting range (demo)
]

URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}


def _ip_in_ranges(ip: str, ranges: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in ranges:
        try:
            if addr in ipaddress.ip_network(cidr):
                return True
        except ValueError:
            continue
    return False


def ip_sanity_check(ip: str) -> dict:
    """
    Deterministic checks that need no external data at all — just IP math.
    Flags: private/reserved IP misuse, known-bad ranges, malformed IPs.
    """
    findings = []
    if not ip:
        return {"is_suspicious": False, "findings": ["no IP provided"]}

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"is_suspicious": True, "findings": ["malformed IP address"]}

    if addr.is_private or addr.is_loopback or addr.is_link_local:
        findings.append("IP is private/reserved — should not appear as a public origin hop")

    if ip in LOCAL_MALICIOUS_IPS:
        findings.append("IP matches local known-malicious IOC list")

    if _ip_in_ranges(ip, SUSPICIOUS_CIDR_RANGES):
        findings.append("IP falls within a known-abused hosting/Tor range")

    return {"is_suspicious": bool(findings), "findings": findings}


def check_local_domain_ioc(domain: str) -> dict:
    """Check a domain against the local IOC list and known campaign data."""
    domain = (domain or "").strip().lower()
    findings = []

    if domain in LOCAL_MALICIOUS_DOMAINS:
        findings.append("domain matches local malicious-domain IOC list")

    if domain in KNOWN_CAMPAIGN_SENDER_DOMAINS:
        findings.append("domain matches a previously observed campaign (feedback-loop data)")

    if domain in URL_SHORTENERS:
        findings.append("domain is a known URL shortener (obfuscation risk)")

    return {"is_flagged": bool(findings), "findings": findings}


def check_sender_domain_campaign_history(sender_domain: str) -> dict:
    """Check if the sender's domain has been seen in prior flagged campaigns."""
    sender_domain = (sender_domain or "").strip().lower()
    if sender_domain in KNOWN_CAMPAIGN_SENDER_DOMAINS:
        return {
            "is_known_campaign": True,
            "findings": [f"sender domain '{sender_domain}' matches known campaign data"],
        }
    return {"is_known_campaign": False, "findings": []}


def gather_local_intelligence(
    sender_domain: str,
    url_domains: list[str],
    earliest_external_ip: str,
) -> dict:
    """
    Single entry point Layer 2 calls to get everything this offline module
    can determine, with zero network dependency. Always returns a result,
    never raises — this is what makes Layer 2 resilient when external APIs
    are unavailable.
    """
    findings: list[str] = []

    ip_result = ip_sanity_check(earliest_external_ip)
    findings.extend(ip_result["findings"])

    campaign_result = check_sender_domain_campaign_history(sender_domain)
    findings.extend(campaign_result["findings"])

    domain_flags = 0
    for domain in url_domains or []:
        d_result = check_local_domain_ioc(domain)
        if d_result["is_flagged"]:
            domain_flags += 1
            findings.extend(d_result["findings"])

    is_suspicious = bool(
        ip_result["is_suspicious"] or campaign_result["is_known_campaign"] or domain_flags > 0
    )

    return {
        "source": "local_deterministic",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "is_suspicious": is_suspicious,
        "flagged_domain_count": domain_flags,
        "ip_flagged": ip_result["is_suspicious"],
        "known_campaign_match": campaign_result["is_known_campaign"],
        "findings": findings,
    }