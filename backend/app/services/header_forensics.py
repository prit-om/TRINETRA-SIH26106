from __future__ import annotations

import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from typing import Any

from app.services.email_parser import _valid_ip

try:
    import dkim
except Exception:
    dkim = None

try:
    import spf
except Exception:
    spf = None

try:
    import dns.resolver
except Exception:
    dns = None
else:
    dns = dns.resolver


DOMAIN_RE = re.compile(r"(?i)^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")


def _domain(address: str) -> str:
    _, parsed = parseaddr(address or "")
    if "@" not in parsed:
        return ""
    return parsed.rsplit("@", 1)[1].strip().lower().rstrip(".")


def _header_domain(raw_value: str | None) -> str:
    if not raw_value:
        return ""
    return _domain(raw_value)


def _result_from_spf_code(code: str | None) -> str:
    if code in {"pass", "fail", "neutral", "none"}:
        return code
    return "none"


import ipaddress

def _get_fast_resolver():
    if dns is None:
        return None
    try:
        res = dns.Resolver()
        res.lifetime = 1.0
        res.timeout = 0.8
        return res
    except Exception:
        return dns


def _get_sending_ip(parsed_fields: dict[str, Any]) -> str:
    c_ip = str(parsed_fields.get("client_ip") or "").strip()
    if c_ip and _valid_ip(c_ip):
        return c_ip
    chain = parsed_fields.get("received_chain") or []
    # Prioritize non-relay public IPs
    for hop in chain:
        ip = hop.get("ip", "")
        if _valid_ip(ip):
            try:
                addr = ipaddress.ip_address(ip)
                if addr.is_global and not addr.is_private and not addr.is_reserved and not (addr.version == 6 and addr in ipaddress.ip_network("2002::/16")):
                    return ip
            except ValueError:
                pass
    for hop in chain:
        ip = hop.get("ip", "")
        if _valid_ip(ip):
            return ip
    return ""


def _spf_result(from_domain: str, sending_ip: str, sender_email: str = "") -> str:
    if not from_domain or not sending_ip:
        return "none"
    if spf is None:
        return "none"

    try:
        # pyspf performs the DNS-backed SPF evaluation.
        result, _explanation = spf.check2(
            i=sending_ip,
            s=sender_email or from_domain,
            h=from_domain,
        )
        return _result_from_spf_code(str(result).lower())
    except Exception:
        return "none"


def _dkim_result(raw_email_bytes: bytes) -> str:
    if dkim is None:
        return "none"
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_email_bytes)
        if not msg.get("DKIM-Signature"):
            return "none"
        verified = dkim.verify(raw_email_bytes)
        return "pass" if verified else "fail"
    except Exception:
        return "none"


def _dmarc_policy(from_domain: str) -> str:
    if not from_domain: return "none"
    resolver = _get_fast_resolver()
    if resolver is None: return "none"
    try:
        answers = resolver.resolve(f"_dmarc.{from_domain}", "TXT", lifetime=1.0)
        txt = "".join(part.decode() if isinstance(part, bytes) else str(part) for answer in answers for part in answer.strings)
        m = re.search(r"(?i)(?:^|;)\s*p\s*=\s*([a-z]+)", txt)
        return m.group(1).lower() if m else "none"
    except Exception: return "none"


def _dmarc_result(from_domain: str):
    if not from_domain:
        return "none"
    resolver = _get_fast_resolver()
    if resolver is None:
        return "none"

    try:
        answers = resolver.resolve(f"_dmarc.{from_domain}", "TXT", lifetime=1.0)
        txt = "".join(
            part.decode() if isinstance(part, bytes) else str(part)
            for answer in answers
            for part in answer.strings
        )
        if not txt.lower().startswith("v=dmarc1"):
            return "none"

        policy_value = re.search(r"(?i)(?:^|;)\s*p\s*=\s*([a-z]+)", txt)
        if not policy_value:
            return "none"

        return "none"
    except Exception:
        return "none"


def _authentication_results_dmarc(message) -> str:
    for value in message.get_all("Authentication-Results", []):
        match = re.search(r"(?i)\bdmarc\s*=\s*(pass|fail|none)", str(value))
        if match:
            return match.group(1).lower()
    return "none"


def _authentication_results_spf(message) -> str:
    for value in message.get_all("Received-SPF", []):
        m = re.search(r"(?i)^\s*(pass|fail|softfail|neutral|none)\b", str(value))
        if m:
            code = m.group(1).lower()
            return "pass" if code == "pass" else ("fail" if code in {"fail", "softfail"} else "none")
    for auth in list(message.get_all("Authentication-Results", [])) + list(
        message.get_all("ARC-Authentication-Results", [])
    ):
        m = re.search(r"(?i)\bspf\s*=\s*(pass|fail|softfail|neutral|none)\b", str(auth))
        if m:
            code = m.group(1).lower()
            return "pass" if code == "pass" else ("fail" if code in {"fail", "softfail"} else "none")
    return ""


def _authentication_results_dkim(message) -> str:
    for auth in list(message.get_all("Authentication-Results", [])) + list(
        message.get_all("ARC-Authentication-Results", [])
    ):
        m = re.search(r"(?i)\bdkim\s*=\s*(pass|fail)\b", str(auth))
        if m:
            return m.group(1).lower()
    return ""


def analyze_headers(raw_email_bytes: bytes, parsed_fields: dict) -> dict:
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw_email_bytes)
    except Exception:
        message = None

    from_domain = _header_domain(message.get("From") if message else "")
    return_path_domain = _header_domain(message.get("Return-Path") if message else "")
    reply_to_domain = _header_domain(message.get("Reply-To") if message else "")

    mismatch = bool(
        from_domain and return_path_domain and from_domain != return_path_domain
    )
    replyto_anomaly = bool(
        reply_to_domain and from_domain and reply_to_domain != from_domain
    )

    sending_ip = _get_sending_ip(parsed_fields)

    # Prefer explicit Authentication-Results / Received-SPF if present
    spf_header_val = _authentication_results_spf(message) if message is not None else ""
    if spf_header_val:
        spf_result = spf_header_val
    else:
        spf_result = _spf_result(from_domain, sending_ip, parsed_fields.get("sender_email", ""))

    dkim_header_val = _authentication_results_dkim(message) if message is not None else ""
    if dkim_header_val:
        dkim_result = dkim_header_val
    else:
        dkim_result = _dkim_result(raw_email_bytes)

    # Prefer an explicit Authentication-Results DMARC result when present.
    if message is not None:
        dmarc_result = _authentication_results_dmarc(message)
        if dmarc_result == "none":
            dmarc_result = _dmarc_result(from_domain)
    else:
        dmarc_result = "none"

    dmarc_policy = _dmarc_policy(from_domain)
    relay_anomalies = []
    chain = parsed_fields.get("relay_forensics", {}) if isinstance(parsed_fields, dict) else {}
    relay_anomalies = chain.get("anomalies", []) if isinstance(chain, dict) else []
    return {
        "from_domain": from_domain,
        "return_path_domain": return_path_domain,
        "reply_to_domain": reply_to_domain,
        "spf_result": spf_result,
        "dkim_result": dkim_result,
        "dmarc_result": dmarc_result,
        "dmarc_policy": dmarc_policy,
        "spf_aligned": bool(spf_result == "pass" and from_domain),
        "dkim_aligned": bool(dkim_result == "pass"),
        "dmarc_aligned": bool(dmarc_result == "pass"),
        "relay_anomalies": relay_anomalies,
        "sender_returnpath_mismatch": mismatch,
        "replyto_anomaly": replyto_anomaly,
        "originating_ip": sending_ip,
        "client_ip": sending_ip,
    }
