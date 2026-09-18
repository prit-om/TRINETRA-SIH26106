"""
Deterministic keyword/pattern-based fallback for NLP content analysis.

This is NOT a replacement for the LLM-based analyze_content() — it is a
lower-quality, zero-dependency, fully-offline fallback that runs when the
LLM is unavailable (no API key, network down, rate limited, etc).

Honest scope: this catches EXPLICIT keyword/phrase patterns. It will miss
paraphrased or context-dependent attacks that don't use flagged language.
It exists so that "LLM unavailable" does not silently mean "scored as
clean" — it gives a real, if weaker, signal instead of a fake zero.

Output shape matches analyze_content() exactly, so risk_fusion.py and
everything downstream needs zero changes to use this as a fallback.
"""

import re

# --- Keyword/pattern banks -------------------------------------------------
# Keep these editable and centralized — this doubles as the "Keyword &
# Pattern Database" component from the architecture diagram.

URGENCY_PATTERNS = [
    r"\burgent(ly)?\b", r"\bimmediately\b", r"\bright away\b", r"\bas soon as possible\b",
    r"\basap\b", r"\btoday\b.*\b(before|by)\b", r"\bdeadline\b", r"\btime[- ]sensitive\b",
    r"\bact now\b", r"\bfinal notice\b", r"\bexpires? (today|soon)\b",
    # Indic / Hinglish urgency patterns
    r"\bturant\b", r"\bjaldi\b", r"\b24 ghante\b", r"\baaj raat\b", r"\bband ho jayega\b",
    r"\bblock ho jayega\b", r"\bconnection cut\b", r"\bconnection kat\b",
]

FINANCIAL_PATTERNS = [
    r"\bwire transfer\b", r"\bbank (details|account)\b", r"\bwiring instructions\b",
    r"\binvoice\b.*\b(pay|payment|process)\b", r"\bgift cards?\b", r"\brouting number\b",
    r"\bswift code\b", r"\biban\b", r"\bpayment (due|required|pending)\b",
    r"\bupdate.*(payment|billing) (details|information)\b",
    r"\btransfer (funds|money)\b", r"\bprocess (a |the )?(payment|transfer)\b",
    # Indic / Hinglish financial patterns
    r"\bkhata\b", r"\bpais[ae]\b", r"\brupay[e]?\b", r"\bbill unpaid\b",
    r"\bpayment karein\b", r"\bbill bharein\b", r"\brashi\b", r"\bshulk\b",
]

CREDENTIAL_HARVEST_PATTERNS = [
    r"\bverify your (account|password|identity)\b", r"\bclick here to (login|verify|reset)\b",
    r"\byour account (will be|has been) (suspended|locked|disabled)\b",
    r"\bconfirm your (password|credentials|details)\b", r"\bunusual (activity|sign-?in)\b",
    r"\bre-?enter your (password|credentials)\b",
    # Indic / Hinglish credential harvesting patterns
    r"\baadhaar\b", r"\bpan card\b", r"\bkyc update\b", r"\bkyc verify\b",
    r"\botp\b", r"\bkhata block\b", r"\bkhata band\b", r"\bpan link\b",
]

EXECUTIVE_IMPERSONATION_PATTERNS = [
    r"\bas (the )?(ceo|cfo|president|director|manager)\b", r"\bon behalf of (the )?(ceo|management|leadership)\b",
    r"\bkeep this (confidential|between us|private)\b", r"\bdon'?t (tell|loop in|cc)\b",
    r"\bi'?m (in a meeting|traveling|unavailable) but need\b", r"\bthis is (a )?confidential (request|matter)\b",
    # Indic / Hinglish executive patterns
    r"\badhikari\b", r"\bprabandhak\b", r"\bkisi ko mat batana\b",
]

SOCIAL_ENGINEERING_PATTERNS = [
    r"\btrust me\b", r"\bplease don'?t (ask|question)\b", r"\bi need you to\b.*\bwithout\b",
    r"\bcan you keep (this|it) (quiet|between us)\b", r"\bno one else (needs to know|should know)\b",
    # Indic / Hinglish social engineering patterns
    r"\bbharosa rakho\b", r"\bkripya dhyan d(o|ein)\b", r"\bshikayat darj\b",
]

AI_GENERATED_HINTS = [
    r"\bas an ai\b", r"\bi (cannot|can'?t) provide\b", r"\bi'?m unable to assist\b",
]


def _pattern_score(text: str, patterns: list[str]) -> float:
    """Return a 0.0-1.0 score based on how many distinct pattern categories hit."""
    if not text:
        return 0.0
    hits = sum(1 for p in patterns if re.search(p, text, flags=re.IGNORECASE))
    if hits == 0:
        return 0.0
    # Scale: 1 hit -> 0.4, 2 hits -> 0.65, 3+ hits -> 0.85 (never claim full 1.0 confidence
    # from keyword matching alone — that's reserved for the real LLM path)
    return min(0.85, 0.4 + (hits - 1) * 0.25)


def analyze_content_fallback(
    subject: str,
    body_text: str,
    sender_email: str = "",
    reply_to: str = "",
) -> dict:
    """
    Deterministic, offline, zero-dependency NLP fallback.
    Same output shape as the LLM-based analyze_content().
    """
    combined_text = f"{subject or ''} {body_text or ''}"

    executive_impersonation_score = _pattern_score(combined_text, EXECUTIVE_IMPERSONATION_PATTERNS)
    urgent_request_score = _pattern_score(combined_text, URGENCY_PATTERNS)
    financial_request_score = _pattern_score(combined_text, FINANCIAL_PATTERNS)
    social_engineering_score = _pattern_score(combined_text, SOCIAL_ENGINEERING_PATTERNS)
    credential_harvesting_score = _pattern_score(combined_text, CREDENTIAL_HARVEST_PATTERNS)
    ai_generated_text_likelihood = _pattern_score(combined_text, AI_GENERATED_HINTS)

    # Build a short, honest, human-readable reasoning string
    fired = []
    if executive_impersonation_score > 0:
        fired.append("executive impersonation language")
    if urgent_request_score > 0:
        fired.append("urgency cues")
    if financial_request_score > 0:
        fired.append("financial/payment request language")
    if credential_harvesting_score > 0:
        fired.append("credential-harvesting phrasing")
    if social_engineering_score > 0:
        fired.append("social engineering phrasing")

    if fired:
        reasoning = (
            "Offline keyword analysis (LLM unavailable) detected: " + ", ".join(fired) + "."
        )
    else:
        reasoning = (
            "Offline keyword analysis (LLM unavailable) found no explicit flagged phrases. "
            "This does NOT confirm the email is safe — subtle or paraphrased attacks may not "
            "be caught without the full NLP model. Rely more heavily on header/URL signals."
        )

    return {
        "executive_impersonation_score": executive_impersonation_score,
        "urgent_request_score": urgent_request_score,
        "financial_request_score": financial_request_score,
        "social_engineering_score": social_engineering_score,
        "credential_harvesting_score": credential_harvesting_score,
        "ai_generated_text_likelihood": ai_generated_text_likelihood,
        "model_reasoning": reasoning,
        "model_used": "offline-keyword-fallback",
    }