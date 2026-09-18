from __future__ import annotations
import hashlib, re
from datetime import datetime, timezone

PII_PATTERNS = {
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "email_password": re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*[^\s,;]+"),
    "national_id": re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b|\b\d{4}[ -]?\d{4}[ -]?\d{4}\b"),
}

def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def mask_pii(text: str) -> tuple[str, list[str]]:
    value = text or ""
    found=[]
    for kind, pattern in PII_PATTERNS.items():
        if pattern.search(value):
            found.append(kind)
            value = pattern.sub(lambda m: "[REDACTED:%s]" % kind, value)
    return value, found

def seal_evidence(raw: bytes, source_name: str = "raw-email") -> dict:
    digest = sha256_bytes(raw)
    return {
        "sha256": digest,
        "algorithm": "SHA-256",
        "byte_length": len(raw),
        "source_name": source_name,
        "sealed_at": datetime.now(timezone.utc).isoformat(),
        "chain_of_custody": [{"event":"evidence_sealed","sha256":digest,"at":datetime.now(timezone.utc).isoformat()}],
    }
