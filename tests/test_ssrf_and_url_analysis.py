import socket
from unittest.mock import MagicMock, patch
import pytest

from app.track_b.url_analysis import (
    is_safe_public_ip,
    resolve_and_validate_host,
    _expand,
    _vt,
    _process_url,
    analyze_urls,
    _get_safe_session,
    _SafeHTTPAdapter,
    _safe_create_connection,
    MAX_RESPONSE_BYTES,
)
from app.track_b.process import process_track_b


def test_is_safe_public_ip_rejects_loopback_and_private():
    # Loopback
    assert not is_safe_public_ip("127.0.0.1")
    assert not is_safe_public_ip("127.255.255.254")
    assert not is_safe_public_ip("::1")

    # RFC 1918 Private networks
    assert not is_safe_public_ip("10.0.0.1")
    assert not is_safe_public_ip("10.255.255.255")
    assert not is_safe_public_ip("172.16.0.1")
    assert not is_safe_public_ip("172.31.255.255")
    assert not is_safe_public_ip("192.168.0.1")
    assert not is_safe_public_ip("192.168.254.254")

    # Link-local & cloud metadata
    assert not is_safe_public_ip("169.254.169.254")
    assert not is_safe_public_ip("fe80::1")

    # Carrier-grade NAT (100.64.0.0/10) & Benchmarking
    assert not is_safe_public_ip("100.64.0.1")
    assert not is_safe_public_ip("198.18.0.1")

    # Multicast, Broadcast, Unspecified
    assert not is_safe_public_ip("224.0.0.1")
    assert not is_safe_public_ip("ff02::1")
    assert not is_safe_public_ip("0.0.0.0")
    assert not is_safe_public_ip("255.255.255.255")
    assert not is_safe_public_ip("::")


def test_is_safe_public_ip_rejects_embedded_ipv6():
    # IPv4-mapped IPv6
    assert not is_safe_public_ip("::ffff:127.0.0.1")
    assert not is_safe_public_ip("::ffff:10.0.0.1")
    assert not is_safe_public_ip("::ffff:169.254.169.254")
    assert is_safe_public_ip("::ffff:8.8.8.8")

    # 6to4 embedding 127.0.0.1 (2002:7f00:0001::)
    assert not is_safe_public_ip("2002:7f00:0001::")


def test_is_safe_public_ip_accepts_valid_public_ips():
    assert is_safe_public_ip("8.8.8.8")
    assert is_safe_public_ip("1.1.1.1")
    assert is_safe_public_ip("93.184.216.34")
    assert is_safe_public_ip("2607:f8b0:4005:805::200e")


def test_resolve_and_validate_host_rejection():
    # Localhost
    safe, reason = resolve_and_validate_host("localhost")
    assert not safe
    assert "Prohibited" in reason or "resolved" in reason

    # Direct private IP host
    safe, reason = resolve_and_validate_host("127.0.0.1")
    assert not safe

    safe, reason = resolve_and_validate_host("169.254.169.254")
    assert not safe

    # Empty host
    safe, reason = resolve_and_validate_host("")
    assert not safe


def test_resolve_and_validate_host_multi_homed_prohibited():
    # If a domain returns multiple IPs where one is private, it must fail closed
    multi_homed_records = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 80)),
    ]
    with patch("socket.getaddrinfo", return_value=multi_homed_records):
        safe, reason = resolve_and_validate_host("evil-multi.example.com")
        assert not safe
        assert "10.0.0.1" in reason


def test_expand_blocks_unsupported_schemes():
    # file:// scheme
    u, hops = _expand("file:///etc/passwd")
    assert u == "file:///etc/passwd"
    assert hops == 0

    # gopher:// scheme
    u, hops = _expand("gopher://127.0.0.1:70/_")
    assert u == "gopher://127.0.0.1:70/_"
    assert hops == 0

    # ftp:// scheme
    u, hops = _expand("ftp://malicious.example.com/test")
    assert u == "ftp://malicious.example.com/test"
    assert hops == 0


def test_expand_blocks_embedded_credentials():
    u, hops = _expand("http://user:pass@127.0.0.1/admin")
    assert hops == 0


def test_expand_blocks_private_destinations():
    u, hops = _expand("http://127.0.0.1:8000/api")
    assert u == "http://127.0.0.1:8000/api"
    assert hops == 0

    u, hops = _expand("http://169.254.169.254/latest/meta-data/")
    assert u == "http://169.254.169.254/latest/meta-data/"
    assert hops == 0


def test_expand_blocks_redirect_to_private_ip():
    # Initial request to safe domain returns 301 to loopback metadata
    mock_resp = MagicMock()
    mock_resp.status_code = 301
    mock_resp.headers = {"Location": "http://169.254.169.254/secret"}

    with patch("requests.Session.get", return_value=mock_resp) as mock_get:
        with patch("app.track_b.url_analysis.resolve_and_validate_host") as mock_val:
            # Hop 1 is safe, Hop 2 (169.254.169.254) is blocked
            mock_val.side_effect = [(True, None), (False, "prohibited IP")]
            expanded, hops = _expand("https://bit.ly/redirect-ssrf")
            # Stopped after first redirect, second request was never sent
            assert hops == 1
            assert "169.254.169.254" in expanded
            # Only 1 GET request occurred (the initial public one)
            assert mock_get.call_count == 1


def test_expand_enforces_redirect_limit():
    responses = [
        MagicMock(status_code=302, headers={"Location": "https://bit.ly/hop1"}, raw=None),
        MagicMock(status_code=302, headers={"Location": "https://bit.ly/hop2"}, raw=None),
        MagicMock(status_code=302, headers={"Location": "https://bit.ly/hop3"}, raw=None),
        MagicMock(status_code=302, headers={"Location": "https://bit.ly/hop4"}, raw=None),
    ]
    with patch("requests.Session.get", side_effect=responses):
        with patch("app.track_b.url_analysis.resolve_and_validate_host", return_value=(True, None)):
            expanded, hops = _expand("https://bit.ly/chain", max_redirects=3)
            assert hops == 3
            assert "hop3" in expanded


def test_air_gapped_mode_makes_zero_requests():
    with patch("requests.Session.get") as mock_session_get:
        with patch("requests.get") as mock_requests_get:
            with patch("socket.getaddrinfo") as mock_dns:
                results = analyze_urls(
                    ["http://bit.ly/test-link", "http://127.0.0.1:8000"],
                    air_gapped=True,
                )
                assert len(results) == 2
                assert mock_session_get.call_count == 0
                assert mock_requests_get.call_count == 0
                assert mock_dns.call_count == 0


def test_air_gapped_mode_remains_offline_after_exception():
    """Confirm that errors in analysis do not trigger any online fallback in air-gapped mode."""
    with patch("socket.getaddrinfo") as mock_dns:
        with patch("requests.Session.get") as mock_http:
            # Force _lookalike to raise an exception
            with patch("app.track_b.url_analysis._lookalike", side_effect=RuntimeError("Simulated error")):
                res = analyze_urls(["https://bit.ly/error-test"], air_gapped=True)
                assert len(res) == 1
                assert mock_dns.call_count == 0
                assert mock_http.call_count == 0

    # Also confirm in process_track_b
    track_a_output = {
        "sender_email": "user@example.com",
        "urls_found": ["http://bit.ly/test"],
        "attachments_found": [],
        "received_chain": [],
        "subject": "Test Air Gapped Error",
        "body_text": "Check http://bit.ly/test",
        "air_gapped": True,
        "header_analysis": {},
        "nlp_analysis": {},
    }
    with patch("app.track_b.process.analyze_urls", side_effect=TypeError("Unexpected signature")):
        with patch("app.track_b.process.synthesize_forensic_reasoning", return_value={"reasoning": "stub"}):
            with patch("socket.getaddrinfo") as mock_dns:
                with patch("requests.get") as mock_http:
                    res = process_track_b(track_a_output, air_gapped=True)
                    assert res["url_findings"] == []
                    assert mock_dns.call_count == 0
                    assert mock_http.call_count == 0


def test_proxy_cannot_bypass_protections(monkeypatch):
    """Verify environment proxies and explicit proxying cannot bypass SSRF controls."""
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:8888")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:8888")

    session = _get_safe_session()
    # Ensure trust_env is disabled
    assert session.trust_env is False
    assert session.proxies == {}

    # Calling proxy_manager_for on the adapter must raise ValueError
    adapter = _SafeHTTPAdapter()
    with pytest.raises(ValueError, match="Proxies are disallowed"):
        adapter.proxy_manager_for("http://127.0.0.1:8888")


def test_https_tls_verification_preserved():
    """Verify that HTTPS requests maintain TLS verification without disabling cert checks."""
    session = _get_safe_session()
    assert session.verify is True

    # Confirm verify=True is supplied in session.get during expansion
    with patch.object(session, "get") as mock_get:
        mock_resp = MagicMock(status_code=200, raw=None)
        mock_get.return_value = mock_resp
        with patch("app.track_b.url_analysis._get_safe_session", return_value=session):
            with patch("app.track_b.url_analysis.resolve_and_validate_host", return_value=(True, None)):
                _expand("https://bit.ly/valid-target")
                assert mock_get.called
                _, kwargs = mock_get.call_args
                assert kwargs.get("verify") is True
                assert kwargs.get("timeout") == (1.5, 1.5)


def test_response_stream_closed_and_size_bounded():
    """Ensure response bodies are bounded and streams are always closed."""
    mock_raw = MagicMock()
    mock_resp = MagicMock(status_code=200, raw=mock_raw)

    with patch("requests.Session.get", return_value=mock_resp):
        with patch("app.track_b.url_analysis.resolve_and_validate_host", return_value=(True, None)):
            _expand("https://bit.ly/test-stream")
            # Raw read must be called with max bound
            mock_raw.read.assert_called_once_with(MAX_RESPONSE_BYTES)
            # Response stream must be closed
            mock_resp.close.assert_called_once()


def test_socket_level_ip_validation_blocks_rebinding():
    """Test that connection-time validation rejects prohibited IPs before socket connection."""
    # Simulate DNS rebinding: host resolution yields loopback IP at socket connect time
    fake_dns = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))
    ]
    with patch("socket.getaddrinfo", return_value=fake_dns):
        with pytest.raises(ValueError, match="SSRF blocked: IP 127.0.0.1"):
            _safe_create_connection(("rebound.example.com", 80))


def test_virustotal_bypassed_in_air_gapped_and_private():
    with patch("requests.get") as mock_get:
        # Air-gapped
        assert not _vt("https://example.com", air_gapped=True)
        assert mock_get.call_count == 0

        # Private IP target
        assert not _vt("http://127.0.0.1", air_gapped=False)
        assert mock_get.call_count == 0

        # Localhost
        assert not _vt("http://localhost:8080", air_gapped=False)
        assert mock_get.call_count == 0


def test_analyze_urls_preserves_contract_and_flags_ssrf():
    res = analyze_urls([
        "http://127.0.0.1/admin",
        "http://localhost:8000",
        "https://sbi-kyc-verify.com",
    ], air_gapped=True)

    expected_keys = {
        "original_url",
        "expanded_url",
        "domain",
        "is_shortened",
        "is_malicious",
        "is_lookalike_domain",
        "redirect_chain_length",
        "reputation",
        "reputation_source",
    }

    for item in res:
        assert expected_keys.issubset(item.keys())

    # Raw IP host
    assert res[0]["is_malicious"] is True
    assert res[0]["reputation"] == "Raw IP Host (Suspicious)"

    # Lookalike
    assert res[2]["is_lookalike_domain"] is True
    assert res[2]["reputation"] == "Lookalike Impersonation"


def test_process_track_b_threads_air_gapped():
    track_a_output = {
        "sender_email": "user@example.com",
        "urls_found": ["http://bit.ly/test"],
        "attachments_found": [],
        "received_chain": [],
        "subject": "Test Air Gapped",
        "body_text": "Check http://bit.ly/test",
        "air_gapped": True,
        "header_analysis": {},
        "nlp_analysis": {},
    }

    with patch("app.track_b.url_analysis._expand") as mock_expand:
        res = process_track_b(track_a_output, air_gapped=True)
        assert "url_findings" in res
        # _expand should have received air_gapped=True
        if mock_expand.called:
            assert mock_expand.call_args[1].get("air_gapped") is True
