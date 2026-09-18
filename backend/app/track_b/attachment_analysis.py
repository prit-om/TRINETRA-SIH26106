from __future__ import annotations
import base64, hashlib, logging, mimetypes
from pathlib import Path
import requests
from .config import get_settings
log=logging.getLogger(__name__)

def _bytes(v):
    if isinstance(v,bytes): return v
    if isinstance(v,bytearray): return bytes(v)
    if isinstance(v,str):
        try: return base64.b64decode(v,validate=True)
        except Exception: return v.encode()
    return b""

def _type(name):
    if not Path(name or "").suffix: return "unknown"
    return mimetypes.guess_type(name)[0] or Path(name).suffix.lstrip(".") or "unknown"

def _vt(h):
    key = get_settings().virustotal_api_key
    if not key:
        return False
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{h}",
            headers={"x-apikey": key},
            timeout=get_settings().virustotal_timeout_seconds
        )
        if r.status_code in (404, 429):
            return False
        r.raise_for_status()
        return int(r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)) > 0
    except Exception as e:
        log.warning("VirusTotal hash lookup failed: %s", e)
        return False

# Dangerous file types frequently leveraged in email attack campaigns
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".hta", ".wsf", ".cpl", ".msi", ".iso", ".img", ".jar"
}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}
DOC_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".png"}

def _inspect_static(name: str, raw: bytes) -> tuple[bool, list[str]]:
    """Inspect attachment filename and raw bytes for threat heuristics."""
    reasons = []
    lower_name = (name or "").lower().strip()
    suffix = Path(lower_name).suffix
    
    # 1. Double extension detection (e.g. invoice.pdf.exe)
    suffixes = [s.lower() for s in Path(lower_name).suffixes]
    if len(suffixes) >= 2:
        if suffixes[-1] in DANGEROUS_EXTENSIONS and any(s in DOC_EXTENSIONS for s in suffixes[:-1]):
            reasons.append(f"Double extension masquerade detected ({''.join(suffixes[-2:])})")
            
    # 2. Standalone high-risk executable/script extension
    if suffix in DANGEROUS_EXTENSIONS:
        reasons.append(f"High-risk executable/script file type ({suffix})")
        
    # 3. Macro-enabled document extension
    if suffix in MACRO_EXTENSIONS:
        reasons.append(f"Macro-enabled active content document ({suffix})")
        
    # 4. Executable magic byte mismatch (PE executable header 'MZ')
    if raw and len(raw) >= 2 and raw[:2] == b"MZ":
        if suffix not in {".exe", ".dll", ".sys"}:
            reasons.append("Windows PE executable magic bytes ('MZ') hidden in non-executable file")
            
    # 5. HTML smuggling check for .html / .htm attachments
    if suffix in {".html", ".htm", ".svg"} and raw:
        sample = raw[:8192].lower()
        if b"msSaveOrOpenBlob" in sample or b"createObjectURL" in sample or b"base64," in sample:
            reasons.append("Potential HTML smuggling / embedded blob payload detected")

    return bool(reasons), reasons

def analyze_attachments(attachments_found: list) -> list:
    out = []
    for a in attachments_found or []:
        name = str(a.get("filename", ""))
        raw = _bytes(a.get("file_bytes", b""))
        h = hashlib.sha256(raw).hexdigest()
        
        vt_flagged = _vt(h)
        heuristic_flagged, heuristic_reasons = _inspect_static(name, raw)
        
        is_flagged = bool(vt_flagged or heuristic_flagged)
        
        if vt_flagged:
            verdict = "Malicious (VirusTotal Known Hash)"
        elif heuristic_flagged:
            verdict = f"Suspicious ({'; '.join(heuristic_reasons)})"
        else:
            verdict = "Clean / Unflagged"
            
        out.append({
            "filename": name,
            "file_type": _type(name),
            "file_hash_sha256": h,
            "hash_reputation_flagged": is_flagged,
            "file_size_bytes": len(raw),
            "verdict": verdict,
            "heuristic_reasons": heuristic_reasons,
        })
    return out
