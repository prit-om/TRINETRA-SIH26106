
"""
Layer 2 — Intelligence + Correlation

Trinetra Hybrid Layer 2 combines:

    1. Local / deterministic intelligence
       -> always available

    2. External intelligence
       -> VirusTotal / URL intelligence
       -> IP / GeoIP intelligence
       -> TOR / VPN / proxy context

    3. Correlation
       -> combines the above into one 0-100 Layer 2 score

Architecture:

    Layer 1
        |
        v
    Layer 2
        |
        +--> Local Intelligence
        |
        +--> URL Threat Intelligence
        |
        +--> IP / Geo Intelligence
        |
        +--> Anonymization Context
        |
        v
    Layer 2 Score
        |
        v
    Layer 3 AI Forensic Reasoning

Important:

    VPN/TOR/proxy detection is contextual evidence.
    It does NOT prove maliciousness or sender attribution.

Layer 2 is deliberately resilient:
if external intelligence is unavailable, local intelligence still
produces a meaningful score.
"""

from __future__ import annotations

from typing import Any

from app.track_b.local_intelligence import (
    gather_local_intelligence,
)


# ===========================================================================
# CONFIGURATION
# ===========================================================================

# Maximum contribution from each evidence family.
#
# These add up to the theoretical maximum of 100:
#
#   Local intelligence       40
#   Malicious URLs           35
#   Lookalike URLs           15
#   Network context          10
#
# However, individual signals are capped inside each category.

LOCAL_MAX_SCORE = 40

MALICIOUS_URL_MAX_SCORE = 35
MALICIOUS_URL_SCORE = 15

LOOKALIKE_URL_MAX_SCORE = 15
LOOKALIKE_URL_SCORE = 5

VPN_PROXY_BONUS = 3
TOR_BONUS = 5
NETWORK_CONTEXT_MAX_SCORE = 8


# ===========================================================================
# HELPERS
# ===========================================================================

def _safe_number(
    value: Any,
    default: float = 0.0,
    minimum: float = 0.0,
    maximum: float = 100.0,
) -> float:
    """
    Safely convert a value to float and clamp it.
    """

    try:
        number = float(value)
    except (TypeError, ValueError):
        return default

    # NaN protection.
    if number != number:
        return default

    return max(
        minimum,
        min(maximum, number),
    )


def _safe_bool(value: Any) -> bool:
    """
    Normalize common boolean representations.
    """

    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        return value.strip().lower() in {
            "true",
            "yes",
            "1",
            "detected",
            "present",
        }

    return bool(value)


def _safe_list(value: Any) -> list:
    """
    Normalize list-like values.
    """

    if isinstance(value, list):
        return value

    if isinstance(value, tuple):
        return list(value)

    return []


def _safe_dict(value: Any) -> dict:
    """
    Normalize optional dictionaries.
    """

    return value if isinstance(value, dict) else {}


# ===========================================================================
# LOCAL INTELLIGENCE
# ===========================================================================

def _calculate_local_score(
    local: dict,
) -> tuple[int, list[str]]:
    """
    Convert local intelligence into a bounded Layer 2 contribution.

    The existing local_intelligence.py exposes is_suspicious and findings.

    Until local_intelligence.py exposes a more granular numerical score,
    a suspicious local result receives a controlled contribution of 40.

    This preserves resilience without allowing malformed local data to
    break the pipeline.
    """

    local = _safe_dict(local)

    findings = [
        str(item)
        for item in _safe_list(
            local.get("findings")
        )
        if item is not None
    ]

    if not _safe_bool(
        local.get(
            "is_suspicious",
            False,
        )
    ):
        return 0, findings

    score = LOCAL_MAX_SCORE

    return score, findings


# ===========================================================================
# URL INTELLIGENCE
# ===========================================================================

def _calculate_url_score(
    url_findings: list,
) -> tuple[int, list[str], dict]:
    """
    Calculate URL intelligence contribution.

    Malicious URL:
        +15 each
        capped at 35

    Lookalike URL:
        +5 each
        capped at 15

    Malicious URLs are treated as stronger evidence than lookalike
    domains because a lookalike signal can occasionally be benign.
    """

    findings = _safe_list(
        url_findings
    )

    malicious_count = 0
    lookalike_count = 0

    for item in findings:

        if not isinstance(item, dict):
            continue

        if _safe_bool(
            item.get(
                "is_malicious",
                False,
            )
        ):
            malicious_count += 1

        if _safe_bool(
            item.get(
                "is_lookalike_domain",
                False,
            )
        ):
            lookalike_count += 1

    malicious_score = min(
        MALICIOUS_URL_MAX_SCORE,
        malicious_count * MALICIOUS_URL_SCORE,
    )

    lookalike_score = min(
        LOOKALIKE_URL_MAX_SCORE,
        lookalike_count * LOOKALIKE_URL_SCORE,
    )

    score = (
        malicious_score
        + lookalike_score
    )

    url_findings_text: list[str] = []

    if malicious_count:
        url_findings_text.append(
            f"{malicious_count} malicious URL(s) "
            "identified by external URL intelligence"
        )

    if lookalike_count:
        url_findings_text.append(
            f"{lookalike_count} lookalike/suspicious "
            "domain URL(s) identified"
        )

    return (
        score,
        url_findings_text,
        {
            "malicious_url_count": malicious_count,
            "malicious_url_score": malicious_score,
            "lookalike_url_count": lookalike_count,
            "lookalike_url_score": lookalike_score,
        },
    )


# ===========================================================================
# NETWORK / GEO INTELLIGENCE
# ===========================================================================

def _calculate_network_context(
    geolocation: dict,
) -> tuple[int, list[str], dict]:
    """
    Calculate contextual network intelligence.

    VPN/proxy:
        +3

    TOR:
        +5

    These are deliberately small because they do not prove maliciousness.
    """

    geo = _safe_dict(
        geolocation
    )

    score = 0
    findings: list[str] = []

    vpn_proxy = _safe_bool(
        geo.get(
            "is_vpn_or_proxy",
            False,
        )
    )

    tor_exit = _safe_bool(
        geo.get(
            "is_tor_exit_node",
            False,
        )
    )

    if vpn_proxy:

        score += VPN_PROXY_BONUS

        findings.append(
            "Origin IP associated with VPN/proxy infrastructure; "
            "treated as contextual evidence"
        )

    if tor_exit:

        score += TOR_BONUS

        findings.append(
            "Origin IP associated with a TOR exit node; "
            "treated as contextual evidence"
        )

    score = min(
        NETWORK_CONTEXT_MAX_SCORE,
        score,
    )

    return (
        score,
        findings,
        {
            "vpn_or_proxy_detected": vpn_proxy,
            "tor_exit_detected": tor_exit,
        },
    )


# ===========================================================================
# EXTERNAL INTELLIGENCE AVAILABILITY
# ===========================================================================

def _external_intelligence_status(
    url_findings: list,
    geolocation: dict,
) -> dict:
    """
    Determine whether external intelligence produced usable evidence.

    IMPORTANT:

    Do not assume that:
        confidence_level == 0

    means:
        API failed.

    A valid external response can legitimately contain zero confidence
    or no malicious finding.

    Therefore this function looks for explicit evidence of a completed
    external analysis where available.
    """

    findings = _safe_list(
        url_findings
    )

    geo = _safe_dict(
        geolocation
    )

    url_external_fields = (
        "is_malicious",
        "is_lookalike_domain",
        "virustotal",
        "vt_score",
        "threat_intelligence",
        "reputation",
    )

    url_has_external_data = any(
        isinstance(item, dict)
        and any(
            field in item
            for field in url_external_fields
        )
        for item in findings
    )

    geo_external_fields = (
        "country",
        "city",
        "isp",
        "confidence_level",
        "is_vpn_or_proxy",
        "is_tor_exit_node",
    )

    geo_has_external_data = any(
        field in geo
        for field in geo_external_fields
    )

    explicitly_failed = (
        _safe_bool(
            geo.get(
                "external_api_failed",
                False,
            )
        )
        or
        _safe_bool(
            geo.get(
                "api_failed",
                False,
            )
        )
    )

    available = (
        not explicitly_failed
        and (
            url_has_external_data
            or geo_has_external_data
        )
    )

    return {
        "available": available,
        "url_external_data": url_has_external_data,
        "geo_external_data": geo_has_external_data,
        "explicit_failure": explicitly_failed,
    }


# ===========================================================================
# MAIN LAYER 2 ENGINE
# ===========================================================================

def compute_layer2_score(
    sender_domain: str,
    url_findings: list[dict],
    geolocation: dict,
    anonymity_report: dict | None = None,
) -> dict:
    """
    Compute the Trinetra Layer 2 intelligence score.

    Parameters
    ----------
    sender_domain:
        Domain extracted from the sender address.

    url_findings:
        Output from url_analysis.analyze_urls().

    geolocation:
        Output from geolocation.geolocate_origin().

    anonymity_report:
        Optional output from analyze_sender_anonymization().

    Returns
    -------
    dict
        Layer 2 score, findings, intelligence provenance, and
        scoring breakdown.
    """

    # ------------------------------------------------------------------
    # Normalize inputs
    # ------------------------------------------------------------------

    sender_domain = str(
        sender_domain or ""
    ).strip().lower()

    url_findings = _safe_list(
        url_findings
    )

    geolocation = _safe_dict(
        geolocation
    )

    anonymity_report = _safe_dict(
        anonymity_report
    )

    # ------------------------------------------------------------------
    # URL domains
    # ------------------------------------------------------------------

    url_domains = [
        str(
            item.get(
                "domain",
                ""
            )
        ).strip().lower()
        for item in url_findings
        if isinstance(item, dict)
        and item.get("domain")
    ]

    # ------------------------------------------------------------------
    # Earliest external IP
    # ------------------------------------------------------------------

    earliest_ip = str(
        geolocation.get(
            "earliest_external_ip",
            "",
        )
        or ""
    ).strip()

    # ------------------------------------------------------------------
    # LOCAL INTELLIGENCE
    # ------------------------------------------------------------------

    local = gather_local_intelligence(
        sender_domain,
        url_domains,
        earliest_ip,
    )

    local_score, local_findings = (
        _calculate_local_score(
            local
        )
    )

    # ------------------------------------------------------------------
    # URL INTELLIGENCE
    # ------------------------------------------------------------------

    (
        url_score,
        url_findings_summary,
        url_breakdown,
    ) = _calculate_url_score(
        url_findings
    )

    # ------------------------------------------------------------------
    # NETWORK / GEO INTELLIGENCE
    # ------------------------------------------------------------------

    (
        network_score,
        network_findings,
        network_breakdown,
    ) = _calculate_network_context(
        geolocation
    )

    # ------------------------------------------------------------------
    # ANONYMIZATION INTELLIGENCE
    # ------------------------------------------------------------------
    #
    # The anonymizer is already represented by the network context.
    #
    # Do not add another score here, otherwise VPN/TOR evidence would
    # be double-counted in Layer 2.
    #
    # We only preserve the intelligence for Layer 3 / Evidence Package.
    # ------------------------------------------------------------------

    anonymization_detected = _safe_bool(
        anonymity_report.get(
            "is_anonymized",
            False,
        )
    )

    anonymization_region = (
        anonymity_report.get(
            "probable_sender_region"
        )
        if anonymity_report
        else None
    )

    # ------------------------------------------------------------------
    # FINAL LAYER 2 SCORE
    # ------------------------------------------------------------------

    score = (
        local_score
        + url_score
        + network_score
    )

    score = int(
        round(
            max(
                0,
                min(
                    100,
                    score,
                ),
            )
        )
    )

    # ------------------------------------------------------------------
    # COMBINED FINDINGS
    # ------------------------------------------------------------------

    findings: list[str] = []

    findings.extend(
        local_findings
    )

    findings.extend(
        url_findings_summary
    )

    findings.extend(
        network_findings
    )

    # ------------------------------------------------------------------
    # External intelligence status
    # ------------------------------------------------------------------

    external_status = (
        _external_intelligence_status(
            url_findings,
            geolocation,
        )
    )

    external_used = external_status[
        "available"
    ]

    # ------------------------------------------------------------------
    # Resilience note
    # ------------------------------------------------------------------

    if external_status["explicit_failure"]:

        resilience_note = (
            "External intelligence reported an "
            "availability failure; Layer 2 retained "
            "local/deterministic intelligence instead "
            "of treating the email as clean."
        )

    elif external_used:

        resilience_note = (
            "Layer 2 combines local/deterministic "
            "intelligence with available external "
            "URL/network intelligence."
        )

    else:

        resilience_note = (
            "No confirmed external intelligence "
            "evidence was available for this request; "
            "Layer 2 retained local/deterministic "
            "intelligence instead of treating the "
            "email as clean."
        )

    # ------------------------------------------------------------------
    # Return
    # ------------------------------------------------------------------

    return {

        "layer2_score": score,

        "layer2_findings": findings,

        "local_intelligence_used": True,

        "external_intelligence_used": external_used,

        "resilience_note": resilience_note,

        # --------------------------------------------------------------
        # Detailed scoring breakdown
        # --------------------------------------------------------------

        "scoring_breakdown": {

            "local_intelligence": {
                "score": local_score,
                "maximum": LOCAL_MAX_SCORE,
            },

            "url_intelligence": {
                "score": url_score,
                "malicious_url_score": (
                    url_breakdown[
                        "malicious_url_score"
                    ]
                ),
                "lookalike_url_score": (
                    url_breakdown[
                        "lookalike_url_score"
                    ]
                ),
                "malicious_url_count": (
                    url_breakdown[
                        "malicious_url_count"
                    ]
                ),
                "lookalike_url_count": (
                    url_breakdown[
                        "lookalike_url_count"
                    ]
                ),
            },

            "network_context": {
                "score": network_score,
                "vpn_proxy_detected": (
                    network_breakdown[
                        "vpn_or_proxy_detected"
                    ]
                ),
                "tor_exit_detected": (
                    network_breakdown[
                        "tor_exit_detected"
                    ]
                ),
            },
        },

        # --------------------------------------------------------------
        # Anonymization intelligence
        # --------------------------------------------------------------
        #
        # No additional score is added here because network context
        # already accounts for VPN/TOR. This prevents double counting.
        # --------------------------------------------------------------

        "anonymization_intelligence": {

            "detected": anonymization_detected,

            "probable_sender_region": (
                anonymization_region
            ),

            "score_contribution": 0,

            "note": (
                "Anonymization is preserved as contextual "
                "intelligence and is not independently "
                "double-counted in Layer 2 scoring."
            ),
        },

        # --------------------------------------------------------------
        # Provenance
        # --------------------------------------------------------------

        "intelligence_provenance": {

            "local": True,

            "external": external_used,

            "url_external_data": external_status[
                "url_external_data"
            ],

            "geo_external_data": external_status[
                "geo_external_data"
            ],

            "explicit_external_failure": (
                external_status[
                    "explicit_failure"
                ]
            ),
        },
    }
