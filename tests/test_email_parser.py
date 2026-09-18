from pathlib import Path

from app.services.email_parser import parse_email

RAW = (Path(__file__).parents[1] / "sample.eml").read_bytes()


def test_parse_email_contract():
    result = parse_email(RAW)

    assert result["sender_email"] == "ceo@company-example.com"
    assert result["sender_display_name"] == "John Smith"
    assert result["reply_to"] == "attacker@fakecompany.net"
    assert result["subject"] == "Urgent Wire Transfer Needed"
    assert "urgent wire transfer" in result["body_text"].lower()
    assert result["urls_found"] == ["http://bit.ly/xyz123"]
    assert result["attachments_found"] == []
    assert len(result["received_chain"]) == 1
    assert result["received_chain"][0]["ip"] == "185.220.101.5"
