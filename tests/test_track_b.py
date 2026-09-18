from app.track_b.risk_fusion import compute_layer1_score, fuse_risk
from app.track_b.geolocation import geolocate_origin
from app.track_b.attachment_analysis import analyze_attachments
from app.track_b.process import process_track_b

def test_fusion_mock():
    h={"spf_result":"fail","dkim_result":"fail","dmarc_result":"fail","sender_returnpath_mismatch":True}
    layer1 = compute_layer1_score(h)
    assert layer1["layer1_score"] == 90  # spf+dkim+dmarc fail + mismatch = 25+25+20+20, no replyto_anomaly set

    layer2 = {"layer2_score": 90, "layer2_findings": ["local IOC match"], "local_intelligence_used": True, "external_intelligence_used": False}
    layer3 = {"final_ai_confidence": 0.95, "evidence_alignment": "corroborated", "forensic_reasoning": "high confidence", "recommended_action": "escalate"}
    result = fuse_risk(layer1, layer2, layer3, [])
    # 90*0.25 + 90*0.25 + 95*0.5 = 22.5 + 22.5 + 47.5 = 92.5 -> Critical
    assert result["classification"] == "Critical"
    assert "evidence_package" in result
    assert result["evidence_package"]["layer1"]["score"] == 90

def test_private_ip_skipped():
    x=geolocate_origin([{"ip":"10.0.0.5"},{"ip":"185.220.101.5"}])
    assert x["earliest_external_ip"]=="185.220.101.5"

def test_no_public_ip():
    x=geolocate_origin([{"ip":"10.0.0.5"},{"ip":"192.168.1.1"}])
    assert x["country"]=="Unknown" and x["confidence_level"]==0

def test_attachment():
    x=analyze_attachments([{"filename":"a.txt","file_bytes":b"hello"}])[0]
    assert x["file_size_bytes"]==5 and len(x["file_hash_sha256"])==64

def test_process(monkeypatch):
    import app.track_b.process as p
    monkeypatch.setattr(p,"analyze_urls",lambda x:[{"domain":"evil.example","is_malicious":True,"is_lookalike_domain":False}])
    monkeypatch.setattr(p,"analyze_attachments",lambda x:[])
    monkeypatch.setattr(p,"geolocate_origin",lambda x:{"earliest_external_ip":"1.2.3.4"})
    out=p.process_track_b({"sender_email":"ceo@example.com","urls_found":["x"],"attachments_found":[],"received_chain":[],
      "subject":"test","body_text":"test body",
      "header_analysis":{"spf_result":"none","dkim_result":"none","dmarc_result":"none","sender_returnpath_mismatch":False},
      "nlp_analysis":{"executive_impersonation_score":0,"urgent_request_score":0,"financial_request_score":0,"social_engineering_score":0}})
    expected_keys = {"risk_score","classification","evidence_package","url_findings","attachment_findings","geolocation","related_case_ids"}
    assert expected_keys.issubset(set(out))
    # Confirm the 3-layer structure is present in the output
    assert {"layer1", "layer2", "layer3"}.issubset(set(out["evidence_package"]))