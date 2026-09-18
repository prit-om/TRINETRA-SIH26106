import app.services.nlp_analysis as nlp


def test_nlp_falls_back_to_keyword_analyzer_without_key(monkeypatch):
    monkeypatch.setattr(
        nlp,
        "_gemini_call",
        lambda prompt: (_ for _ in ()).throw(TimeoutError("simulated timeout")),
    )
    result = nlp.analyze_content(
        "Urgent payment",
        "Please transfer funds immediately.",
        "ceo@example.com",
        "attacker@example.net",
    )

    # No longer a flat zero dict — falls back to the deterministic keyword analyzer,
    # which should pick up the urgency + financial-request language in this test email.
    assert result["model_used"] == "offline-keyword-fallback"
    assert result["urgent_request_score"] > 0
    assert result["financial_request_score"] > 0