from __future__ import annotations
import base64, logging
from difflib import SequenceMatcher
from urllib.parse import urlparse
import requests
import ipaddress
from .config import get_settings
log=logging.getLogger(__name__)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at"
}

BRANDS = {
    # Global technology & finance
    "paypal.com", "microsoft.com", "google.com", "chase.com",
    "apple.com", "amazon.com", "facebook.com", "instagram.com",
    "linkedin.com", "outlook.com", "office.com", "github.com",
    "netflix.com", "dropbox.com",
    # Indian Banking & Finance (SIH26106 focus)
    "onlinesbi.sbi", "sbi.co.in", "hdfcbank.com", "icicibank.com",
    "axisbank.com", "pnbindia.in", "bankofbaroda.in", "kotak.com", "rbi.org.in",
    # Indian Government & Citizen Services (SIH26106 focus)
    "incometax.gov.in", "gst.gov.in", "epfindia.gov.in",
    "uidai.gov.in", "digilocker.gov.in", "parivahan.gov.in",
    "india.gov.in", "nic.in"
}

def _domain(url: str) -> str:
    try:
        n = urlparse(url).netloc.lower().split("@")[-1]
        return n.split(":")[0].strip()
    except Exception:
        return ""

def _is_ip_host(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        ipaddress.ip_address(host)
        return True
    except (ValueError, AttributeError):
        return False

def _lookalike(d: str) -> bool:
    if not d:
        return False
    d = d.lower().strip()
    for b in BRANDS:
        if d == b or d.endswith("." + b):
            continue
        brand_name = b.split(".")[0]
        # Target token / hyphen lookalike (e.g. sbi-kyc-login.com, incometax-refund.in)
        if len(brand_name) >= 3:
            parts = d.replace("-", ".").split(".")
            if brand_name in parts:
                return True
        if SequenceMatcher(None, d, b).ratio() >= 0.82:
            return True
    return False

def _expand(url: str) -> tuple[str, int]:
    try:
        timeout = min(1.5, float(get_settings().virustotal_timeout_seconds))
        r = requests.get(
            url,
            allow_redirects=True,
            timeout=timeout,
            stream=True,
            headers={"User-Agent": "TrinetraAI/1.0"}
        )
        u = r.url or url
        n = len(r.history)
        r.close()
        return u, n
    except Exception as e:
        log.warning("URL resolution failed for %s: %s", url, e)
        return url, 0

def _vt(url: str) -> bool:
    key = get_settings().virustotal_api_key
    if not key:
        return False
    try:
        timeout = min(1.5, float(get_settings().virustotal_timeout_seconds))
        ident = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{ident}",
            headers={"x-apikey": key},
            timeout=timeout
        )
        if r.status_code in (404, 429):
            return False
        r.raise_for_status()
        return int(r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)) > 0
    except Exception as e:
        log.warning("VirusTotal URL lookup failed: %s", e)
        return False

def _process_url(original: str) -> dict:
    original = str(original).strip()
    orig_domain = _domain(original)
    is_short = orig_domain in SHORTENERS

    if is_short:
        expanded, count = _expand(original)
        d = _domain(expanded)
    else:
        expanded, count = original, 0
        d = orig_domain

    # Instant offline heuristics
    is_ip = _is_ip_host(expanded)
    has_auth_spoof = "@" in urlparse(original).netloc
    is_lookalike = _lookalike(d)

    # Only query VirusTotal if not already definitively flagged by heuristics
    vt_flagged = False
    if not (is_lookalike or is_ip or has_auth_spoof):
        vt_flagged = _vt(expanded)

    is_malicious = bool(vt_flagged or is_ip or has_auth_spoof)

    reputation = "Clean"
    if vt_flagged:
        reputation = "VirusTotal Flagged"
    elif is_ip:
        reputation = "Raw IP Host (Suspicious)"
    elif has_auth_spoof:
        reputation = "Credential Auth Spoofing"
    elif is_lookalike:
        reputation = "Lookalike Impersonation"

    return {
        "original_url": original,
        "expanded_url": expanded,
        "domain": d,
        "is_shortened": is_short,
        "is_malicious": is_malicious,
        "is_lookalike_domain": is_lookalike,
        "redirect_chain_length": int(count),
        "reputation": reputation,
        "reputation_source": "VirusTotal" if vt_flagged else "TRINETRA Heuristics",
    }

def analyze_urls(urls_found: list) -> list:
    if not urls_found:
        return []
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=min(4, len(urls_found))) as executor:
        return list(executor.map(_process_url, urls_found))
