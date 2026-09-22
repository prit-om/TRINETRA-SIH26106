from __future__ import annotations

import logging
from email.utils import parseaddr
from typing import Any

from .url_analysis import analyze_urls
from .attachment_analysis import analyze_attachments
from .geolocation import geolocate_origin
from .layer2_engine import compute_layer2_score
from .ai_forensic_reasoning import synthesize_forensic_reasoning
from .risk_fusion import compute_layer1_score, fuse_risk
from .correlation import find_related_cases
from app.track_b.anonymizer_tracer import analyze_sender_anonymization

logger = logging.getLogger(__name__)


def _domain(addr: str) -> str:
    """Safely extract and normalize an email domain."""
    try:
        _, email_address = parseaddr(addr or "")
        if "@" not in email_address:
            return ""

        return email_address.rsplit("@", 1)[1].lower().rstrip(".")
    except Exception:
        return ""


def _as_dict(value: Any) -> dict:
    """Return a dictionary or an empty dictionary."""
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list:
    """Return a list or an empty list."""
    return value if isinstance(value, list) else []


def process_track_b(
    track_a_output: dict,
    db_connection=None,
    air_gapped: bool = False,
) -> dict:
    """
    Execute the complete Trinetra Track B pipeline.

    Order:
        1. Evidence collection
        2. Layer 1 header forensics
        3. Layer 2 local/external intelligence
        4. Layer 3 AI forensic reasoning
        5. Risk fusion
        6. Historical correlation

    Returns one normalized evidence package for the API/report layer.
    """

    if not isinstance(track_a_output, dict):
        raise TypeError("track_a_output must be a dictionary")

    # ------------------------------------------------------------------
    # INPUT NORMALIZATION
    # ------------------------------------------------------------------
    air_gapped = bool(air_gapped or track_a_output.get("air_gapped", False))

    sender_email = str(track_a_output.get("sender_email") or "").strip()
    sender_display_name = str(
        track_a_output.get("sender_display_name") or ""
    ).strip()
    reply_to = str(track_a_output.get("reply_to") or "").strip()
    subject = str(track_a_output.get("subject") or "").strip()
    body_text = str(track_a_output.get("body_text") or "")

    sender_domain = _domain(sender_email)

    urls_found = _as_list(track_a_output.get("urls_found"))
    attachments_found = _as_list(
        track_a_output.get("attachments_found")
    )
    received_chain = _as_list(track_a_output.get("received_chain"))

    header_analysis = _as_dict(
        track_a_output.get("header_analysis")
    )
    nlp_analysis = _as_dict(
        track_a_output.get("nlp_analysis")
    )

    # ------------------------------------------------------------------
    # EVIDENCE COLLECTION
    # ------------------------------------------------------------------

    try:
        url_findings = analyze_urls(urls_found) or []
    except Exception as exc:
        logger.exception("URL analysis failed: %s", exc)
        url_findings = []

    try:
        attachment_findings = analyze_attachments(
            attachments_found
        ) or []
    except Exception as exc:
        logger.exception("Attachment analysis failed: %s", exc)
        attachment_findings = []

    client_ip = str(
        track_a_output.get("client_ip")
        or header_analysis.get("client_ip")
        or header_analysis.get("originating_ip")
        or ""
    ).strip()

    try:
        geolocation = geolocate_origin(received_chain, client_ip=client_ip) or {}
    except Exception as exc:
        logger.exception("Geolocation analysis failed: %s", exc)
        geolocation = {
            "country": "Unknown",
            "city": "Unknown",
            "isp": "Unknown",
            "earliest_external_ip": "",
            "is_vpn_or_proxy": False,
            "is_tor_exit_node": False,
            "error": "Geolocation unavailable",
        }

    geolocation = _as_dict(geolocation)

    # ------------------------------------------------------------------
    # ANONYMIZATION / TRACER INTELLIGENCE
    # ------------------------------------------------------------------

    origin_ip = str(
        geolocation.get("earliest_external_ip") or ""
    ).strip()

    try:
        anonymization_report = (
            analyze_sender_anonymization(
                origin_ip=origin_ip,
                headers=header_analysis,
                resolved_country=geolocation.get(
                    "country",
                    "Unknown",
                ),
            )
            or {}
        )
    except Exception as exc:
        logger.exception(
            "Sender anonymization analysis failed: %s",
            exc,
        )
        anonymization_report = {
            "error": "Anonymization analysis unavailable"
        }

    anonymization_report = _as_dict(anonymization_report)

    geolocation["anonymization_intelligence"] = (
        anonymization_report
    )

    probable_region = anonymization_report.get(
        "probable_sender_region"
    )
    if probable_region:
        geolocation["probable_sender_region"] = probable_region

    # ------------------------------------------------------------------
    # LAYER 1 — DETERMINISTIC HEADER FORENSICS
    # ------------------------------------------------------------------

    try:
        layer1_result = compute_layer1_score(
            header_analysis
        )
    except Exception as exc:
        logger.exception(
            "Layer 1 computation failed: %s",
            exc,
        )
        raise RuntimeError(
            "Layer 1 header forensics failed"
        ) from exc

    layer1_result = _as_dict(layer1_result)

    # ------------------------------------------------------------------
    # LAYER 2 — LOCAL + EXTERNAL INTELLIGENCE
    # ------------------------------------------------------------------

    try:
        layer2_result = compute_layer2_score(
            sender_domain=sender_domain,
            url_findings=url_findings,
            geolocation=geolocation,
            anonymity_report=anonymization_report,
        )
    except TypeError:
        # Compatibility with an older Layer 2 implementation.
        try:
            layer2_result = compute_layer2_score(
                sender_domain,
                url_findings,
                geolocation,
            )
        except Exception as exc:
            logger.exception(
                "Layer 2 computation failed: %s",
                exc,
            )
            raise RuntimeError(
                "Layer 2 intelligence computation failed"
            ) from exc
    except Exception as exc:
        logger.exception(
            "Layer 2 computation failed: %s",
            exc,
        )
        raise RuntimeError(
            "Layer 2 intelligence computation failed"
        ) from exc

    layer2_result = _as_dict(layer2_result)
    layer2_result["anonymization_intelligence"] = (
        anonymization_report
    )

    # ------------------------------------------------------------------
    # LAYER 3 — AI FORENSIC REASONING
    # ------------------------------------------------------------------

    try:
        try:
            layer3_result = synthesize_forensic_reasoning(
                subject=subject,
                body_text=body_text,
                header_analysis=header_analysis,
                layer2_result=layer2_result,
                geolocation=geolocation,
                nlp_analysis=nlp_analysis,
                air_gapped=air_gapped,
            )
        except TypeError:
            layer3_result = synthesize_forensic_reasoning(
                subject=subject,
                body_text=body_text,
                header_analysis=header_analysis,
                layer2_result=layer2_result,
                geolocation=geolocation,
                nlp_analysis=nlp_analysis,
            )
    except Exception as exc:
        logger.exception(
            "Layer 3 reasoning failed: %s",
            exc,
        )
        raise RuntimeError(
            "Layer 3 forensic reasoning failed"
        ) from exc

    layer3_result = _as_dict(layer3_result)

    # ------------------------------------------------------------------
    # FINAL RISK FUSION
    # ------------------------------------------------------------------

    try:
        fusion = fuse_risk(
            layer1_result,
            layer2_result,
            layer3_result,
            attachment_findings,
            anonymization_report,
        )
    except TypeError:
        # Compatibility with the previous four-argument implementation.
        try:
            fusion = fuse_risk(
                layer1_result,
                layer2_result,
                layer3_result,
                attachment_findings,
            )
        except Exception as exc:
            logger.exception(
                "Risk fusion failed: %s",
                exc,
            )
            raise RuntimeError(
                "Final risk fusion failed"
            ) from exc
    except Exception as exc:
        logger.exception(
            "Risk fusion failed: %s",
            exc,
        )
        raise RuntimeError(
            "Final risk fusion failed"
        ) from exc

    fusion = _as_dict(fusion)

    # ------------------------------------------------------------------
    # HISTORICAL CORRELATION
    # ------------------------------------------------------------------

    url_domains = [
        str(item.get("domain")).strip()
        for item in url_findings
        if isinstance(item, dict)
        and item.get("domain")
    ]

    attachment_hashes = [
        str(
            item.get("file_hash_sha256")
            or item.get("sha256")
            or item.get("hash")
        ).strip()
        for item in attachment_findings
        if isinstance(item, dict)
        and (
            item.get("file_hash_sha256")
            or item.get("sha256")
            or item.get("hash")
        )
    ]

    indicators = {
        "sender_email": sender_email,
        "sender_domain": sender_domain,
        "url_domains": url_domains,
        "attachment_hashes": attachment_hashes,
        "earliest_external_ip": origin_ip,
    }

    if db_connection is not None:
        try:
            related_case_ids = find_related_cases(
                indicators,
                db_connection,
            ) or []
        except Exception as exc:
            logger.exception(
                "Historical correlation failed: %s",
                exc,
            )
            related_case_ids = []
    else:
        related_case_ids = []

    # ------------------------------------------------------------------
    # NORMALIZED FINAL RESULT
    # ------------------------------------------------------------------

    risk_score = fusion.get("risk_score", 0)
    classification = fusion.get(
        "classification",
        "unknown",
    )

    return {
        "risk_score": risk_score,
        "classification": classification,
        "evidence_package": fusion.get(
            "evidence_package",
            {},
        ),

        # Canonical layer names used by the report/UI.
        "layer1": layer1_result,
        "layer2": layer2_result,
        "layer3": layer3_result,

        # Backward-compatible names.
        "layer1_result": layer1_result,
        "layer2_result": layer2_result,
        "layer3_result": layer3_result,

        "risk_fusion": fusion,

        "sender_email": sender_email,
        "sender_display_name": sender_display_name,
        "reply_to": reply_to,
        "sender_domain": sender_domain,
        "subject": subject,
        "body_text": body_text,

        "header_analysis": header_analysis,
        "nlp_analysis": nlp_analysis,

        "url_findings": url_findings,
        "attachment_findings": attachment_findings,

        "geolocation": geolocation,
        "anonymization_intelligence": (
            anonymization_report
        ),

        "related_cases": related_case_ids,
        "related_case_ids": related_case_ids,

        "historical_indicators": indicators,
        "air_gapped": air_gapped,
        "engine_mode": (
            "Air-Gapped Sovereign (Zero Cloud Exfiltration)"
            if air_gapped
            else "Hybrid Dual-Engine (Cloud Gemini + Local Failover)"
        ),
    }