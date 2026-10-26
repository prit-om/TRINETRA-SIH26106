import os
from pathlib import Path
from fastapi.testclient import TestClient

# Enable DEMO_MODE for baseline suite compatibility
os.environ["DEMO_MODE"] = "true"

from app.main import app
client = TestClient(app)


def test_health():
    r = client.get('/health')
    assert r.status_code == 200 and r.json()['status'] == 'ok'


def test_analyze_with_stubbed_nlp(monkeypatch):
    import app.routes.analyze as route
    monkeypatch.setattr(
        route,
        'analyze_content',
        lambda **kwargs: {
            'executive_impersonation_score': 0.9,
            'urgent_request_score': 0.95,
            'financial_request_score': 0.9,
            'social_engineering_score': 0.8,
            'credential_harvesting_score': 0.1,
            'ai_generated_text_likelihood': 0.2,
            'model_reasoning': 'Urgent financial language requests an unusual transfer.',
        },
    )
    raw = (Path(__file__).parents[1] / 'sample.eml').read_bytes()
    r = client.post('/analyze', files={'file': ('sample.eml', raw, 'message/rfc822')})
    assert r.status_code == 200
    d = r.json()
    assert 0 <= d['risk_score'] <= 100
    assert d['classification'] in {'Suspicious', 'Phishing', 'Critical', 'Low Risk', 'Safe'}
    assert d['url_findings'][0]['original_url'] == 'http://bit.ly/xyz123'
    assert len(d['evidence']['sha256']) == 64 and d['relay_forensics']['hop_count'] == 1


def test_case_history_and_pdf():
    r = client.get('/cases')
    assert r.status_code == 200 and isinstance(r.json(), list)


# ===========================================================================
# SECURITY TESTS: PHASE 1 SECURITY VERIFICATION
# ===========================================================================

def test_unauthenticated_access_with_keys_configured(monkeypatch):
    """When API keys are configured, unauthenticated requests must be rejected with 401."""
    import app.config as config
    from app.config import Settings

    s = Settings(analyst_api_key="analyst-secret-key", investigator_api_key="investigator-secret-key", demo_mode=False)
    monkeypatch.setattr(config, "get_settings", lambda: s)
    import app.routes.analyze as route
    monkeypatch.setattr(route, "get_settings", lambda: s)

    # Missing credentials in headers -> 401 Unauthorized across all sensitive routes
    assert client.get('/cases').status_code == 401
    assert client.get('/alerts').status_code == 401
    assert client.get('/cases/test-case-id').status_code == 401
    assert client.get('/cases/test-case-id/verify').status_code == 401
    assert client.get('/cases/test-case-id/report.pdf').status_code == 401
    assert client.get('/monitor/status').status_code == 401
    assert client.post('/monitor/start', data={'username': 'u', 'password': 'p', 'imap_server': 's'}).status_code == 401
    assert client.post('/monitor/stop').status_code == 401
    assert client.post('/analyze', data={'raw_text': 'Subject: test\n\nbody'}).status_code == 401


def test_unauthenticated_access_with_keys_absent_and_demo_disabled(monkeypatch):
    """When API keys are absent and demo mode is disabled, sensitive routes fail closed with 503."""
    import app.config as config
    from app.config import Settings

    s = Settings(analyst_api_key=None, investigator_api_key=None, demo_mode=False)
    monkeypatch.setattr(config, "get_settings", lambda: s)
    import app.routes.analyze as route
    monkeypatch.setattr(route, "get_settings", lambda: s)
    monkeypatch.delenv("DEMO_MODE", raising=False)

    # Unconfigured production environment fails closed (503)
    assert client.get('/cases').status_code == 503
    assert client.get('/alerts').status_code == 503
    assert client.get('/cases/test-case-id').status_code == 503
    assert client.get('/cases/test-case-id/verify').status_code == 503
    assert client.get('/cases/test-case-id/report.pdf').status_code == 503
    assert client.post('/analyze', data={'raw_text': 'Subject: test\n\nbody'}).status_code == 503


def test_explicitly_enabled_local_demo_mode(monkeypatch):
    """When demo mode is explicitly enabled, analyst access works, but investigator ops are blocked."""
    import app.config as config
    from app.config import Settings
    from app.services.db import save_case

    s = Settings(analyst_api_key=None, investigator_api_key=None, demo_mode=True)
    monkeypatch.setattr(config, "get_settings", lambda: s)
    import app.routes.analyze as route
    monkeypatch.setattr(route, "get_settings", lambda: s)
    monkeypatch.setenv("DEMO_MODE", "true")

    case_id = "test-demo-mode-case-1"
    save_case(
        {
            "case_id": case_id,
            "risk_score": 15,
            "classification": "Safe",
            "subject": "Demo",
            "sender_email": "demo@example.com",
            "evidence": {"sha256": "112233"},
        },
        b"From: demo@example.com\n\nRaw email body",
        role="analyst",
    )

    # Analyst operations succeed
    assert client.get('/cases').status_code == 200
    assert client.get('/alerts').status_code == 200
    r_case = client.get(f'/cases/{case_id}')
    assert r_case.status_code == 200
    assert 'raw_email' not in r_case.json()

    # Investigator-only operations are strictly blocked in demo mode -> 403 Forbidden
    r_verify = client.get(f'/cases/{case_id}/verify')
    assert r_verify.status_code == 403


def test_analyst_attempts_to_access_investigator_only_operations(monkeypatch):
    """An authenticated analyst cannot access raw evidence or verify hashes."""
    import app.config as config
    from app.config import Settings
    from app.services.db import save_case

    s = Settings(analyst_api_key="analyst-secret-key", investigator_api_key="investigator-secret-key", demo_mode=False)
    monkeypatch.setattr(config, "get_settings", lambda: s)
    import app.routes.analyze as route
    monkeypatch.setattr(route, "get_settings", lambda: s)

    case_id = "test-analyst-restriction-case"
    save_case(
        {
            "case_id": case_id,
            "risk_score": 30,
            "classification": "Low Risk",
            "subject": "Invoice",
            "sender_email": "billing@example.com",
            "evidence": {"sha256": "445566"},
        },
        b"From: billing@example.com\n\nConfidential raw email",
        role="analyst",
    )

    headers = {'x-trinetra-api-key': 'analyst-secret-key'}

    # Analyst can retrieve case, but raw_email is omitted
    r_case = client.get(f'/cases/{case_id}', headers=headers)
    assert r_case.status_code == 200
    assert 'raw_email' not in r_case.json()

    # Analyst calling /verify is forbidden -> 403
    r_verify = client.get(f'/cases/{case_id}/verify', headers=headers)
    assert r_verify.status_code == 403


def test_client_supplied_investigator_role_cannot_grant_privileges(monkeypatch):
    """A client passing role=investigator via form or query cannot elevate privileges."""
    import app.config as config
    from app.config import Settings
    from app.services.db import save_case

    s = Settings(analyst_api_key="analyst-secret-key", investigator_api_key="investigator-secret-key", demo_mode=False)
    monkeypatch.setattr(config, "get_settings", lambda: s)
    import app.routes.analyze as route
    monkeypatch.setattr(route, "get_settings", lambda: s)
    monkeypatch.setattr(
        route,
        'analyze_content',
        lambda **kwargs: {
            'executive_impersonation_score': 0.1,
            'urgent_request_score': 0.1,
            'financial_request_score': 0.1,
            'social_engineering_score': 0.1,
            'credential_harvesting_score': 0.1,
            'ai_generated_text_likelihood': 0.1,
            'model_reasoning': 'Benign message.',
        },
    )

    headers = {'x-trinetra-api-key': 'analyst-secret-key'}

    # 1. Query parameter role=investigator on GET /cases/{id} must not leak raw_email
    case_id = "test-role-spoof-case"
    save_case(
        {
            "case_id": case_id,
            "risk_score": 5,
            "classification": "Safe",
            "subject": "Hello",
            "sender_email": "hello@example.com",
            "evidence": {"sha256": "778899"},
        },
        b"From: hello@example.com\n\nSecret payload",
        role="analyst",
    )
    r_get = client.get(f'/cases/{case_id}?role=investigator', headers=headers)
    assert r_get.status_code == 200
    assert 'raw_email' not in r_get.json()

    # 2. Form parameter role=investigator on POST /analyze with analyst key must mask PII
    raw_text = "From: user@example.com\nSubject: Test\n\nMy PAN is ABCDE1234F and Aadhaar is 1234 5678 9012"
    r_post = client.post(
        '/analyze',
        data={'raw_text': raw_text, 'role': 'investigator'},
        headers=headers,
    )
    assert r_post.status_code == 200
    resp_body = r_post.json().get('body_text', '')
    assert 'ABCDE1234F' not in resp_body
    assert '[REDACTED:national_id]' in resp_body


def test_invalid_credentials_rejected(monkeypatch):
    """Requests presenting invalid or malformed tokens in headers must be rejected with 401."""
    import app.config as config
    from app.config import Settings

    s = Settings(analyst_api_key="analyst-secret-key", investigator_api_key="investigator-secret-key", demo_mode=False)
    monkeypatch.setattr(config, "get_settings", lambda: s)
    import app.routes.analyze as route
    monkeypatch.setattr(route, "get_settings", lambda: s)

    # 1. Bad x-trinetra-api-key
    assert client.get('/cases', headers={'x-trinetra-api-key': 'wrong-key'}).status_code == 401
    assert client.get('/alerts', headers={'x-trinetra-api-key': 'wrong-key'}).status_code == 401

    # 2. Bad Authorization: Bearer
    assert client.get('/cases', headers={'authorization': 'Bearer wrong-bearer-token'}).status_code == 401


def test_authenticated_investigator_access(monkeypatch):
    """An authenticated investigator retains access through case retrieval, verify, and analysis."""
    import app.config as config
    from app.config import Settings
    from app.services.db import save_case
    import hashlib

    s = Settings(analyst_api_key="analyst-secret-key", investigator_api_key="investigator-secret-key", demo_mode=False)
    monkeypatch.setattr(config, "get_settings", lambda: s)
    import app.routes.analyze as route
    monkeypatch.setattr(route, "get_settings", lambda: s)

    raw_bytes = b"From: ceo@example.com\nSubject: Investigation\n\nUnredacted raw text for LEA"
    expected_hash = hashlib.sha256(raw_bytes).hexdigest()
    case_id = "test-investigator-full-access"
    save_case(
        {
            "case_id": case_id,
            "risk_score": 75,
            "classification": "Phishing",
            "subject": "Investigation",
            "sender_email": "ceo@example.com",
            "evidence": {"sha256": expected_hash},
        },
        raw_bytes,
        role="investigator",
    )

    inv_headers = {'x-trinetra-api-key': 'investigator-secret-key'}

    # Investigator gets raw email in case retrieval
    r_case = client.get(f'/cases/{case_id}', headers=inv_headers)
    assert r_case.status_code == 200
    assert r_case.json().get('raw_email') == raw_bytes.decode('utf-8')

    # Investigator can verify evidence hash -> 200 and valid: True
    r_verify = client.get(f'/cases/{case_id}/verify', headers=inv_headers)
    assert r_verify.status_code == 200
    assert r_verify.json()['valid'] is True


def test_query_parameter_authentication_disallowed(monkeypatch):
    """Query parameter authentication is not permitted (CWE-598); headers are required."""
    import app.config as config
    from app.config import Settings

    s = Settings(analyst_api_key="analyst-secret-key", investigator_api_key="investigator-secret-key", demo_mode=False)
    monkeypatch.setattr(config, "get_settings", lambda: s)
    import app.routes.analyze as route
    monkeypatch.setattr(route, "get_settings", lambda: s)

    # Supplying API key via query parameter must be ignored and return 401
    assert client.get('/cases?api_key=analyst-secret-key').status_code == 401
    assert client.get('/cases?x_trinetra_api_key=analyst-secret-key').status_code == 401
