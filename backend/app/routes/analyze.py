from __future__ import annotations

import base64
import os
import uuid
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, Header, UploadFile
from fastapi.responses import Response

from app.config import get_settings
from app.integrations.track_b import process_track_b
from app.services.email_parser import parse_email
from app.services.header_forensics import analyze_headers
from app.services.nlp_analysis import analyze_content
from app.services.evidence import seal_evidence, mask_pii
from app.services.relay_forensics import analyze_relay_chain
from app.services.domain_intelligence import analyze_domains
from app.services.db import (
    save_case,
    list_cases,
    get_case,
    find_related,
    alerts,
)
from app.track_b.graph_intelligence import build_ioc_graph
from app.track_b.neo4j_client import persist_graph
from app.track_b.attribution import score_attribution
from app.track_b.monitor import (
    start as start_monitor,
    stop as stop_monitor,
    status as monitor_status,
)


router = APIRouter()


# ============================================================
# ROLE / ACCESS CONTROL
# ============================================================

def _authenticate_request(
    x_trinetra_api_key: str | None = None,
    authorization: str | None = None,
    require_investigator: bool = False,
) -> str:
    """
    Authenticate and authorize requests strictly via request headers.

    Rules:
    - Query-parameter authentication is disallowed (CWE-598).
    - Credentials must be provided via 'x-trinetra-api-key' or 'Authorization: Bearer <key>'.
    - If API keys are configured (ANALYST_API_KEY or INVESTIGATOR_API_KEY):
      * Missing or invalid credentials return 401 Unauthorized.
      * Matching INVESTIGATOR_API_KEY grants 'investigator' role.
      * Matching ANALYST_API_KEY grants 'analyst' role.
      * If an endpoint requires investigator role, analysts receive 403 Forbidden.
    - If no API keys are configured:
      * If DEMO_MODE is not enabled (default), fails closed with 503 Service Unavailable
        to prevent silent public exposure of sensitive endpoints in unconfigured deployments.
      * If DEMO_MODE is explicitly enabled:
        - The caller is assigned 'analyst' role.
        - The caller CANNOT gain 'investigator' privileges by requesting them.
        - Any endpoint requiring investigator privileges returns 403 Forbidden.
    """
    s = get_settings()

    token = None
    if x_trinetra_api_key and str(x_trinetra_api_key).strip():
        token = str(x_trinetra_api_key).strip()
    elif authorization and str(authorization).strip():
        auth_val = str(authorization).strip()
        token = auth_val[7:].strip() if auth_val.lower().startswith("bearer ") else auth_val

    has_investigator_key = bool(s.investigator_api_key and s.investigator_api_key.strip())
    has_analyst_key = bool(s.analyst_api_key and s.analyst_api_key.strip())
    keys_configured = has_investigator_key or has_analyst_key
    demo_mode_enabled = bool(
        getattr(s, "demo_mode", False)
        or os.getenv("DEMO_MODE", "").lower() in {"true", "1", "yes"}
    )

    if keys_configured:
        if not token:
            raise HTTPException(
                status_code=401,
                detail="Authentication required: missing API key in headers.",
            )

        if has_investigator_key and token == s.investigator_api_key.strip():
            return "investigator"

        if has_analyst_key and token == s.analyst_api_key.strip():
            if require_investigator:
                raise HTTPException(
                    status_code=403,
                    detail="Investigator privileges required.",
                )
            return "analyst"

        raise HTTPException(
            status_code=401,
            detail="Authentication failed: invalid API key.",
        )

    # API keys are absent/unconfigured:
    if not demo_mode_enabled:
        raise HTTPException(
            status_code=503,
            detail="Server security configuration error: API keys are not configured. Configure ANALYST_API_KEY and INVESTIGATOR_API_KEY, or set DEMO_MODE=true for local development.",
        )

    # Explicit Demo Mode (local development only)
    if require_investigator:
        raise HTTPException(
            status_code=403,
            detail="Investigator privileges require a configured INVESTIGATOR_API_KEY.",
        )

    return "analyst"


def _role(api_key: str | None, requested: str = "analyst") -> str:
    """
    Backwards compatibility helper for resolving role from API key.
    Note: 'requested' is ignored; role is determined strictly by credentials.
    """
    s = get_settings()
    token = str(api_key).strip() if api_key else ""
    if s.investigator_api_key and token == s.investigator_api_key.strip():
        return "investigator"
    if s.analyst_api_key and token == s.analyst_api_key.strip():
        return "analyst"
    return "analyst"


# ============================================================
# JSON-SAFE TRACK-A CONVERSION
# ============================================================

def _json_safe_track_a(x):
    result = dict(x)

    result["attachments_found"] = [
        {
            **a,
            "file_bytes": (
                base64.b64encode(
                    a.get("file_bytes", b"")
                ).decode("ascii")
                if isinstance(a.get("file_bytes"), bytes)
                else a.get("file_bytes", "")
            ),
        }
        for a in result.get("attachments_found", [])
    ]

    return result


# ============================================================
# SUMMARY
# ============================================================

def _build_summary(n, h):
    candidates = [
        (
            "executive impersonation",
            n.get("executive_impersonation_score", 0),
        ),
        (
            "urgent requests",
            n.get("urgent_request_score", 0),
        ),
        (
            "financial requests",
            n.get("financial_request_score", 0),
        ),
        (
            "social engineering",
            n.get("social_engineering_score", 0),
        ),
        (
            "credential harvesting",
            n.get("credential_harvesting_score", 0),
        ),
        (
            "sender/Return-Path mismatch",
            1 if h.get("sender_returnpath_mismatch") else 0,
        ),
        (
            "Reply-To anomaly",
            1 if h.get("replyto_anomaly") else 0,
        ),
    ]

    active = [
        x[0]
        for x in sorted(
            candidates,
            key=lambda z: z[1],
            reverse=True,
        )
        if x[1] >= 0.35
    ]

    if not active:
        return (
            "This email shows no strong content or "
            "header threat signals."
        )

    return (
        "This email shows signs of "
        + " and ".join(active[:2])
        + "."
    )


# ============================================================
# CORE ANALYSIS PIPELINE
# ============================================================

def analyze_raw(
    raw_email_bytes: bytes,
    source="manual",
    requested_role="analyst",
    filename="email.eml",
    evidence_override=None,
    stored_raw=None,
    air_gapped: bool = False,
):
    if not raw_email_bytes:
        raise ValueError("Email artifact is empty")

    # --------------------------------------------------------
    # 1. Chain-of-custody evidence
    # --------------------------------------------------------

    evidence = (
        evidence_override
        or seal_evidence(
            raw_email_bytes,
            filename,
        )
    )

    # --------------------------------------------------------
    # 2. Parse email
    # --------------------------------------------------------

    parsed = parse_email(
        raw_email_bytes
    )

    # --------------------------------------------------------
    # 3. Relay / Received-chain forensics
    # --------------------------------------------------------

    relay = analyze_relay_chain(
        parsed["received_chain"]
    )

    # --------------------------------------------------------
    # 4. Header forensics
    # --------------------------------------------------------

    parsed_for_headers = dict(parsed)
    parsed_for_headers["relay_forensics"] = relay

    header = analyze_headers(
        raw_email_bytes,
        parsed_for_headers,
    )

    # --------------------------------------------------------
    # 5. NLP / content analysis
    # --------------------------------------------------------

    nlp = analyze_content(
        subject=parsed["subject"],
        body_text=parsed["body_text"],
        sender_email=parsed["sender_email"],
        reply_to=parsed["reply_to"],
        air_gapped=air_gapped,
    )

    # --------------------------------------------------------
    # 6. Track A
    # --------------------------------------------------------

    track_a = {
        **parsed,
        "header_analysis": header,
        "nlp_analysis": nlp,
    }

    # --------------------------------------------------------
    # 7. Track B
    # --------------------------------------------------------

    tb = process_track_b(
        _json_safe_track_a(track_a),
        air_gapped=air_gapped,
    )

    # --------------------------------------------------------
    # 8. Sender domain
    #
    # IMPORTANT:
    # This value must be passed to build_ioc_graph()
    # using the correct named parameter.
    # --------------------------------------------------------

    sender_domain = (
        parsed["sender_email"].rsplit("@", 1)[-1]
        if "@" in parsed["sender_email"]
        else ""
    )

    # --------------------------------------------------------
    # 9. Domain intelligence
    # --------------------------------------------------------

    domains = analyze_domains(
        [
            x.get("domain")
            for x in tb["url_findings"]
        ]
        + [sender_domain]
    )

    # --------------------------------------------------------
    # 10. Create case ID BEFORE graph construction
    #
    # This fixes the previous design where the graph was
    # created with an empty case ID and modified afterward.
    # --------------------------------------------------------

    case_id = str(uuid.uuid4())

    # --------------------------------------------------------
    # 11. Build IOC graph
    #
    # IMPORTANT:
    # build_ioc_graph() expects:
    #
    # case_id
    # sender_email
    # sender_domain
    # geolocation
    # url_findings
    # attachment_findings
    #
    # Named arguments prevent positional schema mismatch.
    # --------------------------------------------------------

    graph = build_ioc_graph(
        case_id=case_id,
        sender_email=parsed["sender_email"],
        sender_domain=sender_domain,
        geolocation=tb["geolocation"],
        url_findings=tb["url_findings"],
        attachment_findings=tb["attachment_findings"],
    )

    # --------------------------------------------------------
    # 12. Persist graph to Neo4j
    # --------------------------------------------------------

    graph["neo4j_connected"] = persist_graph(
        graph,
        case_id,
    )

    # --------------------------------------------------------
    # 13. Determine access role
    # --------------------------------------------------------

    role = (
        requested_role
        if requested_role in {"investigator", "lea"}
        else "analyst"
    )

    # --------------------------------------------------------
    # 14. PII masking
    # --------------------------------------------------------

    masked_body, pii_types = mask_pii(
        parsed["body_text"]
    )

    # --------------------------------------------------------
    # 15. Initial report
    # --------------------------------------------------------

    report = {
        "case_id": case_id,

        "risk_score": int(
            tb["risk_score"]
        ),

        "classification": str(
            tb["classification"]
        ),

        "summary": _build_summary(
            nlp,
            header,
        ),

        "air_gapped": air_gapped,

        "engine_mode": tb.get(
            "engine_mode",
            "Air-Gapped Sovereign (Zero Cloud Exfiltration)" if air_gapped else "Hybrid Dual-Engine (Cloud Gemini + Local Failover)",
        ),

        "sender_email": parsed[
            "sender_email"
        ],

        "sender_display_name": parsed[
            "sender_display_name"
        ],

        "reply_to": parsed[
            "reply_to"
        ],

        "subject": parsed[
            "subject"
        ],

        "body_text": (
            parsed["body_text"]
            if role in {"investigator", "lea"}
            else masked_body
        ),

        "pii_detected": pii_types,

        "evidence": evidence,

        "header_analysis": header,

        "relay_forensics": relay,

        "nlp_analysis": nlp,

        "url_findings": tb[
            "url_findings"
        ],

        "attachment_findings": tb[
            "attachment_findings"
        ],

        "geolocation": tb[
            "geolocation"
        ],

        "domain_intelligence": domains,

        "evidence_package": tb.get(
            "evidence_package",
            {},
        ),

        "graph": graph,

        "related_case_ids": tb.get(
            "related_case_ids",
            [],
        ),

        "source": source,

        "raw_access": (
            "restricted_to_investigator"
        ),
    }

    # --------------------------------------------------------
    # 16. Historical correlation
    # --------------------------------------------------------

    related = find_related(
        case_id,
        parsed["sender_email"],
        [
            x.get("domain")
            for x in tb["url_findings"]
        ],
        tb["geolocation"].get(
            "earliest_external_ip"
        ),
        [
            a.get("file_hash_sha256")
            for a in tb[
                "attachment_findings"
            ]
        ],
    )

    report["related_case_ids"] = related

    # --------------------------------------------------------
    # 17. Attribution engine
    # --------------------------------------------------------

    report["attribution"] = score_attribution(
        header,
        tb["geolocation"],
        tb["url_findings"],
        len(related),
        graph,
    )

    # --------------------------------------------------------
    # 18. Save case
    # --------------------------------------------------------

    save_case(
        report,
        (
            stored_raw
            if stored_raw is not None
            else raw_email_bytes
        ),
        role,
    )

    # --------------------------------------------------------
    # 19. Refresh historical correlation after saving
    # --------------------------------------------------------

    report["related_case_ids"] = find_related(
        case_id,
        parsed["sender_email"],
        [
            x.get("domain")
            for x in tb["url_findings"]
        ],
        tb["geolocation"].get(
            "earliest_external_ip"
        ),
        [
            a.get("file_hash_sha256")
            for a in tb[
                "attachment_findings"
            ]
        ],
    )

    return report


# ============================================================
# POST /analyze
# ============================================================

@router.post("/analyze")
async def analyze(
    file: UploadFile | None = File(default=None),
    raw_text: str | None = Form(default=None),
    role: str = Form(default="analyst"),
    air_gapped: bool = Form(default=False),
    x_trinetra_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
):
    # --------------------------------------------------------
    # Server-side authentication and role resolution
    # --------------------------------------------------------
    auth_role = _authenticate_request(
        x_trinetra_api_key=x_trinetra_api_key,
        authorization=authorization,
    )

    # --------------------------------------------------------
    # Input validation
    # --------------------------------------------------------

    if file is None and not raw_text:
        raise HTTPException(
            400,
            "Provide an email file or raw_text.",
        )

    if file is not None and raw_text:
        raise HTTPException(
            400,
            "Provide either a file or raw_text, not both.",
        )

    # --------------------------------------------------------
    # Read input
    # --------------------------------------------------------

    raw = (
        await file.read()
        if file
        else raw_text.encode("utf-8")
    )

    # --------------------------------------------------------
    # Size limit
    # --------------------------------------------------------

    if (
        len(raw)
        > get_settings().max_upload_bytes
    ):
        raise HTTPException(
            413,
            "Email artifact exceeds the configured size limit.",
        )

    name = (
        file.filename
        if file
        else "pasted-email.eml"
    )

    # Preserve original uploaded artifact
    original_raw = raw

    # Seal original artifact BEFORE MSG conversion
    evidence_override = seal_evidence(
        original_raw,
        name,
    )

    # --------------------------------------------------------
    # MSG conversion
    # --------------------------------------------------------

    if (
        file
        and Path(name).suffix.lower()
        == ".msg"
    ):
        try:
            import extract_msg
            import tempfile

            with tempfile.NamedTemporaryFile(
                suffix=".msg",
                delete=False,
            ) as tmp:
                tmp.write(raw)
                tmp_path = tmp.name

            try:
                m = extract_msg.Message(
                    tmp_path
                )

                headers = (
                    m.header or ""
                )

                raw = (
                    headers
                    + "\r\n\r\n"
                    + (m.body or "")
                ).encode(
                    "utf-8",
                    "replace",
                )

            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        except Exception as exc:
            raise HTTPException(
                400,
                (
                    "MSG parsing requires "
                    "extract-msg and a valid "
                    "Outlook MSG artifact."
                ),
            ) from exc

    # --------------------------------------------------------
    # Execute complete analysis pipeline
    # --------------------------------------------------------

    try:
        return analyze_raw(
            raw,
            "manual",
            auth_role,
            name,
            evidence_override=evidence_override,
            stored_raw=original_raw,
            air_gapped=air_gapped,
        )

    except ValueError as exc:
        raise HTTPException(
            400,
            str(exc),
        ) from exc

    except Exception as exc:
        # Temporary diagnostic logging.
        # Keep this until the full backend pipeline is verified.

        import traceback

        print(
            "\n========== ANALYZE FAILED =========="
        )

        print(
            f"Exception type: {type(exc).__name__}"
        )

        print(
            f"Exception: {exc}"
        )

        traceback.print_exc()

        print(
            "====================================\n"
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Email analysis failed: "
                f"{type(exc).__name__}: {exc}"
            ),
        ) from exc


# ============================================================
# CASE LIST
# ============================================================

@router.get("/cases")
def cases(
    x_trinetra_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
):
    _authenticate_request(
        x_trinetra_api_key=x_trinetra_api_key,
        authorization=authorization,
    )
    return list_cases()


# ============================================================
# HIGH-RISK ALERTS
# ============================================================

@router.get("/alerts")
def high_risk_alerts(
    x_trinetra_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
):
    _authenticate_request(
        x_trinetra_api_key=x_trinetra_api_key,
        authorization=authorization,
    )
    return alerts()


# ============================================================
# GET SINGLE CASE
# ============================================================

@router.get("/cases/{case_id}")
def case(
    case_id: str,
    x_trinetra_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
):
    auth_role = _authenticate_request(
        x_trinetra_api_key=x_trinetra_api_key,
        authorization=authorization,
    )

    data = get_case(
        case_id,
        include_raw=auth_role in {
            "investigator",
            "lea",
        },
    )

    if not data:
        raise HTTPException(
            404,
            "Case not found",
        )

    return data


# ============================================================
# VERIFY CASE
# ============================================================

@router.get("/cases/{case_id}/verify")
def verify_case(
    case_id: str,
    x_trinetra_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
):
    _authenticate_request(
        x_trinetra_api_key=x_trinetra_api_key,
        authorization=authorization,
        require_investigator=True,
    )

    import hashlib

    data = get_case(
        case_id,
        True,
    )

    if (
        not data
        or "raw_email" not in data
    ):
        raise HTTPException(
            404,
            "Case evidence not available",
        )

    digest = hashlib.sha256(
        data["raw_email"].encode("utf-8")
    ).hexdigest()

    expected = (
        data.get(
            "evidence",
            {},
        ).get("sha256")
        or data.get(
            "evidence_sha256"
        )
    )

    return {
        "case_id": case_id,
        "algorithm": "SHA-256",
        "expected": expected,
        "computed": digest,
        "valid": digest == expected,
    }


# ============================================================
# PDF REPORT
# ============================================================

@router.get("/cases/{case_id}/report.pdf")
def case_pdf(
    case_id: str,
    x_trinetra_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
):
    _authenticate_request(
        x_trinetra_api_key=x_trinetra_api_key,
        authorization=authorization,
    )

    from app.track_b.pdf_report import (
        generate_pdf_report
    )

    data = get_case(
        case_id,
        False,
    )

    if not data:
        raise HTTPException(
            404,
            "Case not found",
        )

    return Response(
        generate_pdf_report(
            case_id,
            data,
        ),
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; '
                f'filename="trinetra-{case_id}.pdf"'
            )
        },
    )


# ============================================================
# MONITOR STATUS
# ============================================================

@router.get("/monitor/status")
def monitor_status_route(
    x_trinetra_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
):
    _authenticate_request(
        x_trinetra_api_key=x_trinetra_api_key,
        authorization=authorization,
    )
    return monitor_status()


# ============================================================
# START IMAP MONITOR
# ============================================================

@router.post("/monitor/start")
def monitor_start(
    username: str = Form(...),
    password: str = Form(...),
    imap_server: str = Form(...),
    folder: str = Form(default="INBOX"),
    interval: int = Form(default=20),
    x_trinetra_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
):
    _authenticate_request(
        x_trinetra_api_key=x_trinetra_api_key,
        authorization=authorization,
    )

    def callback(
        raw,
        source="imap",
    ):
        try:
            return analyze_raw(
                raw,
                source,
                "analyst",
                "imap-message.eml",
            )

        except Exception as exc:
            return {
                "classification": "Error",
                "error": str(exc),
            }

    return start_monitor(
        username,
        password,
        imap_server,
        folder,
        callback,
        interval,
    )


# ============================================================
# STOP IMAP MONITOR
# ============================================================

@router.post("/monitor/stop")
def monitor_stop(
    x_trinetra_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
):
    _authenticate_request(
        x_trinetra_api_key=x_trinetra_api_key,
        authorization=authorization,
    )
    return stop_monitor()