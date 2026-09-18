from pathlib import Path

from app.services.email_parser import parse_email
from app.services.header_forensics import analyze_headers

RAW = (Path(__file__).parents[1] / "sample.eml").read_bytes()


def test_header_anomalies_and_safe_fallbacks():
    parsed = parse_email(RAW)
    result = analyze_headers(RAW, parsed)

    assert result["sender_returnpath_mismatch"] is True
    assert result["replyto_anomaly"] is True
    assert result["spf_result"] in {"pass", "fail", "neutral", "none"}
    assert result["dkim_result"] in {"pass", "fail", "none"}
    assert result["dmarc_result"] in {"pass", "fail", "none"}
