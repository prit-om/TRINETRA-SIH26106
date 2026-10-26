from __future__ import annotations

import base64
import ipaddress
import logging
import socket
from difflib import SequenceMatcher
from urllib.parse import urljoin, urlparse, urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.util import connection as urllib3_connection

from .config import get_settings

log = logging.getLogger(__name__)

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

# Special-use networks not always covered by standard non-global checks
_CARRIER_GRADE_NAT = ipaddress.IPv4Network("100.64.0.0/10")
_BENCHMARK_NET = ipaddress.IPv4Network("198.18.0.0/15")
_RFC6052_PREFIX = ipaddress.IPv6Network("64:ff9b::/96")

MAX_RESPONSE_BYTES = 4096


def is_safe_public_ip(ip_str: str) -> bool:
    """
    Validate that an IP address is a safe, publicly routable unicast IP.

    Rejects:
    - Loopback (127.0.0.0/8, ::1)
    - Private RFC 1918 / RFC 4193 networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
    - Link-local (169.254.0.0/16, fe80::/10) including cloud metadata (169.254.169.254)
    - Multicast (224.0.0.0/4, ff00::/8)
    - Reserved/Unspecified (0.0.0.0/8, ::, 240.0.0.0/4)
    - Carrier-grade NAT (100.64.0.0/10)
    - Benchmark networks (198.18.0.0/15)
    - IPv4-mapped IPv6 (::ffff:0:0/96) mapping to prohibited IPv4
    - 6to4 (2002::/16) and Teredo embedding prohibited IPv4
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip())

        # Unpack IPv6 embedded/mapped IPv4 representations
        if isinstance(ip, ipaddress.IPv6Address):
            if ip.ipv4_mapped:
                return is_safe_public_ip(str(ip.ipv4_mapped))
            if ip.sixtofour:
                return is_safe_public_ip(str(ip.sixtofour))
            if ip.teredo:
                return is_safe_public_ip(str(ip.teredo[1]))
            if ip in _RFC6052_PREFIX:
                embedded_v4 = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
                return is_safe_public_ip(str(embedded_v4))

        if not ip.is_global:
            return False

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False

        if isinstance(ip, ipaddress.IPv4Address):
            if ip in _CARRIER_GRADE_NAT or ip in _BENCHMARK_NET:
                return False

        return True
    except Exception:
        return False


def resolve_and_validate_host(
    host: str,
    port: int = 80,
    air_gapped: bool = False,
) -> tuple[bool, str | None]:
    """
    Resolve a hostname and verify that ALL candidate IP addresses are safe public IPs.
    Fails closed if any candidate IP is prohibited or resolution fails.
    When air_gapped=True, completely avoids live DNS lookups.
    """
    clean_host = host.strip("[]").strip()
    if not clean_host:
        return False, "Empty host"

    # Check for direct IP literal
    try:
        ipaddress.ip_address(clean_host)
        if not is_safe_public_ip(clean_host):
            return False, f"Host is prohibited IP literal: {clean_host}"
        return True, None
    except ValueError:
        pass

    # Check known local/internal hostnames
    lower_host = clean_host.lower()
    if lower_host in {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}:
        return False, f"Prohibited local hostname: {clean_host}"

    if air_gapped:
        # In air-gapped mode, never perform live DNS resolution
        return True, None

    try:
        res_list = socket.getaddrinfo(
            clean_host,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
        if not res_list:
            return False, f"No DNS records found for host {clean_host}"

        for res in res_list:
            ip_str = res[4][0]
            if not is_safe_public_ip(ip_str):
                return False, f"Host {clean_host} resolved to prohibited IP {ip_str}"

        return True, None
    except socket.gaierror as exc:
        return False, f"DNS resolution failed for {clean_host}: {exc}"
    except Exception as exc:
        return False, f"Resolution error for {clean_host}: {exc}"


def _safe_create_connection(
    address: tuple[str, int],
    timeout=urllib3_connection._DEFAULT_TIMEOUT,
    source_address=None,
    socket_options=None,
):
    """
    Socket factory that verifies DNS at connection time and connects directly
    to the validated IP, mitigating DNS rebinding and TOCTOU.
    """
    host, port = address
    clean_host = host.strip("[]").strip()

    res_list = socket.getaddrinfo(clean_host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    if not res_list:
        raise OSError(f"No DNS records for {clean_host}")

    for res in res_list:
        cand_ip = res[4][0]
        if not is_safe_public_ip(cand_ip):
            raise ValueError(f"SSRF blocked: IP {cand_ip} for {clean_host} is not a safe public IP")

    # Connect directly to the exact IP that passed validation
    af, socktype, proto, _canonname, sa = res_list[0]
    sock = socket.socket(af, socktype, proto)
    try:
        if socket_options:
            urllib3_connection._set_socket_options(sock, socket_options)
        if timeout is not urllib3_connection._DEFAULT_TIMEOUT:
            sock.settimeout(timeout)
        if source_address:
            sock.bind(source_address)
        sock.connect(sa)
        return sock
    except Exception:
        sock.close()
        raise


class _SafeHTTPConnection(HTTPConnection):
    def _new_conn(self) -> socket.socket:
        return _safe_create_connection(
            (self._dns_host, self.port),
            self.timeout,
            self.source_address,
            self.socket_options,
        )


class _SafeHTTPSConnection(HTTPSConnection):
    def _new_conn(self) -> socket.socket:
        return _safe_create_connection(
            (self._dns_host, self.port),
            self.timeout,
            self.source_address,
            self.socket_options,
        )


class _SafeHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = _SafeHTTPConnection


class _SafeHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _SafeHTTPSConnection


class _SafeHTTPAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)
        self.poolmanager.pool_classes_by_scheme["http"] = _SafeHTTPConnectionPool
        self.poolmanager.pool_classes_by_scheme["https"] = _SafeHTTPSConnectionPool

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        raise ValueError("Proxies are disallowed for URL expansion to prevent SSRF bypass")


def _get_safe_session() -> requests.Session:
    s = requests.Session()
    s.trust_env = False  # NEVER use HTTP_PROXY / HTTPS_PROXY from environment
    s.proxies = {}       # Ensure no default proxies are configured
    adapter = _SafeHTTPAdapter(max_retries=0, pool_connections=1, pool_maxsize=1)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


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


def _expand(
    url: str,
    air_gapped: bool = False,
    max_redirects: int = 3,
) -> tuple[str, int]:
    """
    Safely expand shortened URLs up to max_redirects hops.
    Enforces scheme validation, per-hop SSRF checks, timeout, and response bounds.
    If air_gapped is True, returns (url, 0) immediately without network calls.
    """
    if air_gapped:
        return url, 0

    current_url = url
    hop = 0
    timeout_val = min(1.5, float(get_settings().virustotal_timeout_seconds))
    timeout_tuple = (timeout_val, timeout_val)

    try:
        session = _get_safe_session()
    except Exception as exc:
        log.warning("Failed to initialize safe HTTP session: %s", exc)
        return url, 0

    try:
        while hop < max_redirects:
            try:
                parsed = urlsplit(current_url)
            except Exception as exc:
                log.warning("Malformed URL during expansion %s: %s", current_url, exc)
                break

            scheme = (parsed.scheme or "").lower()
            if scheme not in ("http", "https"):
                log.warning("SSRF blocked unsupported scheme '%s' in URL %s", scheme, current_url)
                break

            host = parsed.hostname
            if not host:
                log.warning("SSRF blocked URL with empty host: %s", current_url)
                break

            # Disallow embedded credentials in URL to avoid spoofing / parsing desync
            if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
                log.warning("SSRF blocked URL with embedded credentials: %s", current_url)
                break

            try:
                port = parsed.port or (443 if scheme == "https" else 80)
            except ValueError:
                log.warning("SSRF blocked URL with invalid port: %s", current_url)
                break

            # Pre-flight DNS & IP check
            is_safe, reason = resolve_and_validate_host(host, port, air_gapped=False)
            if not is_safe:
                log.warning("SSRF pre-flight check rejected URL %s: %s", current_url, reason)
                break

            # Execute single hop with automatic redirects disabled
            r = None
            try:
                r = session.get(
                    current_url,
                    allow_redirects=False,
                    timeout=timeout_tuple,
                    stream=True,
                    headers={
                        "User-Agent": "TrinetraAIVision/1.0",
                        "Connection": "close",
                    },
                    verify=True,
                )

                # Cap response body reading to strict size limit
                if r.raw:
                    try:
                        _ = r.raw.read(MAX_RESPONSE_BYTES)
                    except Exception:
                        pass

                # Check for redirect status
                if r.status_code in (301, 302, 303, 307, 308):
                    location = r.headers.get("Location")
                    if not location:
                        break
                    next_url = urljoin(current_url, location.strip())
                    if next_url == current_url:
                        break
                    current_url = next_url
                    hop += 1
                else:
                    break
            except Exception as exc:
                log.warning("URL expansion request failed for %s: %s", current_url, exc)
                break
            finally:
                if r is not None:
                    r.close()

        return current_url, hop
    except Exception as exc:
        log.warning("Unexpected error during URL expansion for %s: %s", url, exc)
        return current_url, hop
    finally:
        session.close()


def _vt(url: str, air_gapped: bool = False) -> bool:
    """
    Query VirusTotal v3 for URL reputation.
    Bypassed if air_gapped=True or if the destination is private/internal.
    """
    if air_gapped:
        return False

    key = get_settings().virustotal_api_key
    if not key:
        return False

    try:
        parsed = urlsplit(url)
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            return False

        host = parsed.hostname
        if not host:
            return False

        # Do not query VirusTotal for private/internal IPs or hosts
        is_safe, _ = resolve_and_validate_host(
            host,
            parsed.port or (443 if scheme == "https" else 80),
            air_gapped=False,
        )
        if not is_safe:
            return False

        timeout_val = min(1.5, float(get_settings().virustotal_timeout_seconds))
        ident = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{ident}",
            headers={"x-apikey": key},
            timeout=(timeout_val, timeout_val),
        )
        try:
            if r.status_code in (404, 429):
                return False
            r.raise_for_status()
            return (
                int(
                    r.json()
                    .get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                    .get("malicious", 0)
                )
                > 0
            )
        finally:
            r.close()
    except Exception as exc:
        log.warning("VirusTotal URL lookup failed: %s", exc)
        return False


def _process_url(original: str, air_gapped: bool = False) -> dict:
    original = str(original).strip()
    orig_domain = _domain(original)
    is_short = orig_domain in SHORTENERS

    if is_short:
        expanded, count = _expand(original, air_gapped=air_gapped)
        d = _domain(expanded)
    else:
        expanded, count = original, 0
        d = orig_domain

    # Instant offline heuristics
    is_ip = _is_ip_host(expanded)
    has_auth_spoof = "@" in urlparse(original).netloc
    is_lookalike = _lookalike(d)

    # SSRF / prohibited destination heuristic check
    is_prohibited_dest = False
    try:
        parsed_exp = urlsplit(expanded)
        exp_scheme = (parsed_exp.scheme or "").lower()
        if exp_scheme and exp_scheme not in ("http", "https"):
            is_prohibited_dest = True
        else:
            exp_host = parsed_exp.hostname
            if exp_host:
                is_safe, _ = resolve_and_validate_host(
                    exp_host,
                    parsed_exp.port or 80,
                    air_gapped=air_gapped,
                )
                if not is_safe:
                    is_prohibited_dest = True
    except Exception:
        pass

    # Only query VirusTotal if not already definitively flagged and not prohibited
    vt_flagged = False
    if not (is_lookalike or is_ip or has_auth_spoof or is_prohibited_dest):
        vt_flagged = _vt(expanded, air_gapped=air_gapped)

    is_malicious = bool(vt_flagged or is_ip or has_auth_spoof or is_prohibited_dest)

    reputation = "Clean"
    if vt_flagged:
        reputation = "VirusTotal Flagged"
    elif is_ip:
        reputation = "Raw IP Host (Suspicious)"
    elif is_prohibited_dest:
        reputation = "Prohibited Host / SSRF Risk"
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


def analyze_urls(urls_found: list, air_gapped: bool = False) -> list:
    if not urls_found or not isinstance(urls_found, list):
        return []
    from concurrent.futures import ThreadPoolExecutor

    def _worker(u):
        try:
            return _process_url(u, air_gapped=air_gapped)
        except Exception as exc:
            log.warning("Failed processing URL '%s': %s", u, exc)
            return {
                "original_url": str(u),
                "expanded_url": str(u),
                "domain": "",
                "is_shortened": False,
                "is_malicious": False,
                "is_lookalike_domain": False,
                "redirect_chain_length": 0,
                "reputation": "Error",
                "reputation_source": "TRINETRA Heuristics",
            }

    with ThreadPoolExecutor(max_workers=min(4, len(urls_found))) as executor:
        return list(executor.map(_worker, urls_found))
