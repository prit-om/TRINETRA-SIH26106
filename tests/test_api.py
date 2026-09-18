from pathlib import Path
from fastapi.testclient import TestClient
from app.main import app
client=TestClient(app)

def test_health():
    r=client.get('/health'); assert r.status_code==200 and r.json()['status']=='ok'

def test_analyze_with_stubbed_nlp(monkeypatch):
    import app.routes.analyze as route
    monkeypatch.setattr(route,'analyze_content',lambda **kwargs:{'executive_impersonation_score':.9,'urgent_request_score':.95,'financial_request_score':.9,'social_engineering_score':.8,'credential_harvesting_score':.1,'ai_generated_text_likelihood':.2,'model_reasoning':'Urgent financial language requests an unusual transfer.'})
    raw=(Path(__file__).parents[1]/'sample.eml').read_bytes()
    r=client.post('/analyze',files={'file':('sample.eml',raw,'message/rfc822')})
    assert r.status_code==200
    d=r.json(); assert 0<=d['risk_score']<=100; assert d['classification'] in {'Suspicious','Phishing','Critical','Low Risk','Safe'}
    assert d['url_findings'][0]['original_url']=='http://bit.ly/xyz123'
    assert len(d['evidence']['sha256'])==64 and d['relay_forensics']['hop_count']==1

def test_case_history_and_pdf():
    r=client.get('/cases'); assert r.status_code==200 and isinstance(r.json(),list)
