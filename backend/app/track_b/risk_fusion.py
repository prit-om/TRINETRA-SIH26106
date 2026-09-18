
"""
Risk Fusion Engine — Trinetra 3-Layer Architecture

The final risk score is based on three primary evidence layers:

    LAYER 1
    Deterministic header forensics
        -> score: 0-100
        -> weight: 30%

    LAYER 2
    Local + external intelligence
        -> score: 0-100
        -> weight: 40%

    LAYER 3
    AI forensic reasoning
        -> confidence: 0.0-1.0
        -> converted to 0-100
        -> weight: 30%

Additional evidence:

    ATTACHMENTS
    Independent supporting evidence
        -> capped bonus

    ANONYMIZATION
    Contextual intelligence only
        -> small capped bonus
        -> VPN/TOR/proxy does NOT prove maliciousness

Final model:

    Base Risk =
        Layer 1 × 0.30
      + Layer 2 × 0.40
      + Layer 3 × 0.30

    Final Risk =
        Base Risk
      + Attachment Bonus
      + Anonymization Bonus

Final score is always clamped to 0-100.

Important architectural principle:
Layer 3 is a reasoning/correlation layer. It does not directly
control the final score. The central risk-fusion engine remains
responsible for the final numerical risk decision.
"""

from __future__ import annotations

from typing import Any


# ===========================================================================
# CONFIGURATION
# ===========================================================================

# Primary risk-layer weights.
# These MUST add up to exactly 1.0.

LAYER1_WEIGHT = 0.30
LAYER2_WEIGHT = 0.40
LAYER3_WEIGHT = 0.30


# Maximum independent bonuses.
#
# These bonuses are deliberately small so that secondary evidence
# cannot overwhelm the three primary evidence layers.

ATTACHMENT_BONUS = 10
ANONYMIZATION_BONUS = 5


# ===========================================================================
# GENERIC HELPERS
# ===========================================================================

def _clamp(
    value: Any,
    lo: float = 0.0,
    hi: float = 100.0,
) -> float:
    """
    Safely convert a value to float and clamp it to [lo, hi].

    Examples:
        _clamp(50)       -> 50.0
        _clamp(150)      -> 100.0
        _clamp(-10)      -> 0.0
        _clamp("75")     -> 75.0
        _clamp("invalid") -> lo
    """

    try:
        value = float(value)
    except (TypeError, ValueError):
        return lo

    # NaN protection.
    if value != value:
        return lo

    return max(lo, min(hi, value))


def _safe_bool(value: Any) -> bool:
    """
    Normalize common boolean representations.

    Examples:
        True       -> True
        "true"     -> True
        "yes"      -> True
        "1"        -> True
        "false"    -> False
        None       -> False
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
    Always return a list.

    Prevents malformed optional data from breaking the fusion engine.
    """

    if isinstance(value, list):
        return value

    if isinstance(value, tuple):
        return list(value)

    return []


def _safe_findings(value: Any) -> list[str]:
    """
    Normalize findings into a list of strings.

    Invalid/non-string entries are converted to strings rather than
    allowing the Evidence Package construction to fail.
    """

    if not isinstance(value, (list, tuple)):
        return []

    return [
        str(item)
        for item in value
        if item is not None
    ]


# ===========================================================================
# LAYER 1 — DETERMINISTIC HEADER FORENSICS
# ===========================================================================

def compute_layer1_score(
    header_analysis: dict | None,
) -> dict:
    """
    Calculate the deterministic Layer 1 header-forensics score.

    Layer 1 examines:

        - SPF
        - DKIM
        - DMARC
        - Sender / Return-Path mismatch
        - Reply-To anomaly
        - Relay-chain anomalies

    Layer 1 does NOT use:

        - NLP
        - URL reputation
        - Attachment reputation
        - Geolocation
        - Gemini

    Maximum raw score is capped at 100.
    """

    h = header_analysis or {}

    if not isinstance(h, dict):
        h = {}

    score = 0.0
    findings: list[str] = []

    # ------------------------------------------------------------------
    # SPF
    # ------------------------------------------------------------------

    if (
        str(
            h.get("spf_result", "")
        )
        .strip()
        .lower()
        == "fail"
    ):
        score += 25

        findings.append(
            "SPF authentication failed"
        )

    # ------------------------------------------------------------------
    # DKIM
    # ------------------------------------------------------------------

    if (
        str(
            h.get("dkim_result", "")
        )
        .strip()
        .lower()
        == "fail"
    ):
        score += 25

        findings.append(
            "DKIM authentication failed"
        )

    # ------------------------------------------------------------------
    # DMARC
    # ------------------------------------------------------------------

    if (
        str(
            h.get("dmarc_result", "")
        )
        .strip()
        .lower()
        == "fail"
    ):
        score += 20

        findings.append(
            "DMARC authentication failed"
        )

    # ------------------------------------------------------------------
    # Sender / Return-Path mismatch
    # ------------------------------------------------------------------

    if _safe_bool(
        h.get(
            "sender_returnpath_mismatch",
            False,
        )
    ):
        score += 20

        findings.append(
            "Sender / Return-Path domain mismatch"
        )

    # ------------------------------------------------------------------
    # Reply-To anomaly
    # ------------------------------------------------------------------

    if _safe_bool(
        h.get(
            "replyto_anomaly",
            False,
        )
    ):
        score += 10

        findings.append(
            "Reply-To domain anomaly"
        )

    # ------------------------------------------------------------------
    # Relay-chain anomalies
    # ------------------------------------------------------------------

    relay_anomalies = _safe_list(
        h.get("relay_anomalies")
    )

    if relay_anomalies:

        relay_bonus = min(
            20,
            5 * len(relay_anomalies),
        )

        score += relay_bonus

        findings.append(
            f"{len(relay_anomalies)} "
            "relay-chain anomaly/anomalies detected"
        )

    return {
        "layer1_score": int(
            round(
                _clamp(score)
            )
        ),
        "layer1_findings": findings,
    }


# ===========================================================================
# ATTACHMENT EVIDENCE
# ===========================================================================

def _compute_attachment_bonus(
    attachment_findings: list | None,
) -> tuple[int, list[str]]:
    """
    Calculate a conservative attachment contribution.

    Current supported signal:

        hash_reputation_flagged == True

    A flagged attachment contributes +10 maximum.

    This can later be extended with:

        - malicious hash
        - suspicious hash
        - static-analysis verdict
        - macro detection
        - executable detection
        - sandbox verdict
    """

    findings = _safe_list(
        attachment_findings
    )

    flagged = [
        item
        for item in findings
        if isinstance(item, dict)
        and _safe_bool(
            item.get(
                "hash_reputation_flagged",
                False,
            )
        )
    ]

    if not flagged:
        return 0, []

    return (
        ATTACHMENT_BONUS,
        [
            f"{len(flagged)} attachment(s) "
            "matched a flagged hash reputation"
        ],
    )


# ===========================================================================
# ANONYMIZATION EVIDENCE
# ===========================================================================

def _compute_anonymization_bonus(
    anonymity_report: dict | None,
) -> tuple[int, list[str]]:
    """
    Calculate a small contextual anonymization bonus.

    IMPORTANT:

        VPN/TOR/proxy usage does NOT prove maliciousness.
        It does NOT prove sender identity.
        It does NOT establish attribution.

    Therefore this signal is deliberately capped at +5.
    """

    report = anonymity_report or {}

    if not isinstance(report, dict):
        return 0, []

    is_anonymized = _safe_bool(
        report.get(
            "is_anonymized",
            False,
        )
    )

    if not is_anonymized:
        return 0, []

    mechanisms: list[str] = []

    if _safe_bool(
        report.get(
            "is_tor_exit_node",
            False,
        )
    ):
        mechanisms.append(
            "TOR exit node"
        )

    if _safe_bool(
        report.get(
            "is_vpn_or_proxy",
            False,
        )
    ):
        mechanisms.append(
            "VPN/proxy"
        )

    if mechanisms:

        mechanism_text = ", ".join(
            mechanisms
        )

        return (
            ANONYMIZATION_BONUS,
            [
                "Sender used anonymization/privacy "
                f"infrastructure ({mechanism_text}); "
                "treated as contextual evidence only"
            ],
        )

    return (
        ANONYMIZATION_BONUS,
        [
            "Sender anonymization infrastructure detected; "
            "treated as contextual evidence only"
        ],
    )


# ===========================================================================
# FINAL RISK FUSION
# ===========================================================================

def fuse_risk(
    layer1_result: dict | None,
    layer2_result: dict | None,
    layer3_result: dict | None,
    attachment_findings: list | None = None,
    anonymity_report: dict | None = None,
) -> dict:
    """
    Combine all Trinetra evidence layers into the final risk result.

    PRIMARY WEIGHTS:

        Layer 1 = 30%
        Layer 2 = 40%
        Layer 3 = 30%

    ADDITIONAL EVIDENCE:

        Attachment reputation = up to +10
        Anonymization context  = up to +5

    The final score is always clamped to 0-100.

    Layer 3 does NOT independently decide the final risk score.
    It provides AI forensic reasoning that is then weighted with
    deterministic and intelligence evidence.
    """

    # ------------------------------------------------------------------
    # Normalize input objects
    # ------------------------------------------------------------------

    l1 = (
        layer1_result
        if isinstance(layer1_result, dict)
        else {}
    )

    l2 = (
        layer2_result
        if isinstance(layer2_result, dict)
        else {}
    )

    l3 = (
        layer3_result
        if isinstance(layer3_result, dict)
        else {}
    )

    # ------------------------------------------------------------------
    # Validate / normalize Layer 1
    # ------------------------------------------------------------------

    layer1_score = _clamp(
        l1.get(
            "layer1_score",
            0,
        ),
        lo=0.0,
        hi=100.0,
    )

    # ------------------------------------------------------------------
    # Validate / normalize Layer 2
    # ------------------------------------------------------------------

    layer2_score = _clamp(
        l2.get(
            "layer2_score",
            0,
        ),
        lo=0.0,
        hi=100.0,
    )

    # ------------------------------------------------------------------
    # Validate / normalize Layer 3
    # ------------------------------------------------------------------
    #
    # Layer 3 returns confidence in [0,1].
    # Convert to the same 0-100 scale used by Layers 1 and 2.
    # ------------------------------------------------------------------

    layer3_confidence = _clamp(
        l3.get(
            "final_ai_confidence",
            0.0,
        ),
        lo=0.0,
        hi=1.0,
    )

    layer3_score = (
        layer3_confidence * 100.0
    )

    # ------------------------------------------------------------------
    # BASE WEIGHTED SCORE
    # ------------------------------------------------------------------

    layer1_contribution = (
        layer1_score * LAYER1_WEIGHT
    )

    layer2_contribution = (
        layer2_score * LAYER2_WEIGHT
    )

    layer3_contribution = (
        layer3_score * LAYER3_WEIGHT
    )

    base_score = (
        layer1_contribution
        + layer2_contribution
        + layer3_contribution
    )

    # ------------------------------------------------------------------
    # ATTACHMENT BONUS
    # ------------------------------------------------------------------

    attachment_bonus, attachment_reasons = (
        _compute_attachment_bonus(
            attachment_findings
        )
    )

    # ------------------------------------------------------------------
    # ANONYMIZATION BONUS
    # ------------------------------------------------------------------

    anonymization_bonus, anonymization_reasons = (
        _compute_anonymization_bonus(
            anonymity_report
        )
    )

    # ------------------------------------------------------------------
    # FINAL SCORE
    # ------------------------------------------------------------------

    final_score = (
        base_score
        + attachment_bonus
        + anonymization_bonus
    )

    final_score = _clamp(
        final_score,
        lo=0.0,
        hi=100.0,
    )

    risk_score = int(
        round(final_score)
    )

    # ------------------------------------------------------------------
    # CLASSIFICATION
    # ------------------------------------------------------------------

    if risk_score <= 19:

        classification = "Safe"

    elif risk_score <= 44:

        classification = "Low Risk"

    elif risk_score <= 69:

        classification = "Suspicious"

    elif risk_score <= 89:

        classification = "Phishing"

    else:

        classification = "Critical"

    # ------------------------------------------------------------------
    # RISK REASONS
    # ------------------------------------------------------------------

    risk_reasons: list[str] = []

    risk_reasons.extend(
        attachment_reasons
    )

    risk_reasons.extend(
        anonymization_reasons
    )

    # ------------------------------------------------------------------
    # Evidence Package
    # ------------------------------------------------------------------

    evidence_package = {

        # ==============================================================
        # LAYER 1
        # ==============================================================

        "layer1": {

            "score": int(
                round(layer1_score)
            ),

            "weight": LAYER1_WEIGHT,

            "weighted_contribution": round(
                layer1_contribution,
                2,
            ),

            "findings": _safe_findings(
                l1.get(
                    "layer1_findings",
                    [],
                )
            ),
        },

        # ==============================================================
        # LAYER 2
        # ==============================================================

        "layer2": {

            "score": int(
                round(layer2_score)
            ),

            "weight": LAYER2_WEIGHT,

            "weighted_contribution": round(
                layer2_contribution,
                2,
            ),

            "findings": _safe_findings(
                l2.get(
                    "layer2_findings",
                    [],
                )
            ),

            "local_intelligence_used": _safe_bool(
                l2.get(
                    "local_intelligence_used",
                    False,
                )
            ),

            "external_intelligence_used": _safe_bool(
                l2.get(
                    "external_intelligence_used",
                    False,
                )
            ),
        },

        # ==============================================================
        # LAYER 3
        # ==============================================================

        "layer3": {

            "confidence": round(
                layer3_confidence,
                3,
            ),

            "score": int(
                round(layer3_score)
            ),

            "weight": LAYER3_WEIGHT,

            "weighted_contribution": round(
                layer3_contribution,
                2,
            ),

            "evidence_alignment": l3.get(
                "evidence_alignment",
                "",
            ),

            "forensic_reasoning": l3.get(
                "forensic_reasoning",
                "",
            ),

            "recommended_action": l3.get(
                "recommended_action",
                "monitor",
            ),

            "reasoning_source": l3.get(
                "reasoning_source",
                "unknown",
            ),
        },

        # ==============================================================
        # ATTACHMENTS
        # ==============================================================

        "attachments": {

            "bonus": attachment_bonus,

            "reasons": attachment_reasons,
        },

        # ==============================================================
        # ANONYMIZATION
        # ==============================================================

        "anonymization": {

            "bonus": anonymization_bonus,

            "reasons": anonymization_reasons,
        },

        # ==============================================================
        # FUSION BREAKDOWN
        # ==============================================================

        "fusion": {

            "formula": (
                "Layer1*0.30 + Layer2*0.40 + "
                "Layer3*0.30 + attachment_bonus + "
                "anonymization_bonus"
            ),

            "base_weighted_score": round(
                base_score,
                2,
            ),

            "layer1_contribution": round(
                layer1_contribution,
                2,
            ),

            "layer2_contribution": round(
                layer2_contribution,
                2,
            ),

            "layer3_contribution": round(
                layer3_contribution,
                2,
            ),

            "attachment_bonus": attachment_bonus,

            "anonymization_bonus": anonymization_bonus,

            "final_score": risk_score,
        },

        # ==============================================================
        # ALL ADDITIONAL REASONS
        # ==============================================================

        "risk_reasons": risk_reasons,
    }

    # ------------------------------------------------------------------
    # FINAL RETURN
    # ------------------------------------------------------------------

    return {
        "risk_score": risk_score,

        "classification": classification,

        "evidence_package": evidence_package,
    }

