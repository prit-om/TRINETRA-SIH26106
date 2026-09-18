from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    KeepTogether,
    PageBreak,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


def _text(value: Any, default: str = "N/A") -> str:
    if value is None or value == "":
        return default

    if isinstance(value, bool):
        return "Yes" if value else "No"

    if isinstance(value, dict):
        return "; ".join(
            f"{key}: {_text(item)}"
            for key, item in value.items()
        )

    if isinstance(value, list):
        return ", ".join(_text(item) for item in value)

    return str(value)


def _paragraph(value: Any, style: ParagraphStyle) -> Paragraph:
    return Paragraph(
        escape(_text(value)).replace("\n", "<br/>"),
        style,
    )


def _dict_table(
    data: Any,
    styles: dict[str, ParagraphStyle],
) -> Table:
    if not isinstance(data, dict) or not data:
        rows = [[
            _paragraph("No data available.", styles["body"]),
        ]]
        table = Table(rows, colWidths=[170 * mm])
        table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D9DEE8")),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7F8FA")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        return table

    rows = [[
        _paragraph("Indicator", styles["table_header"]),
        _paragraph("Result", styles["table_header"]),
    ]]

    for key, value in data.items():
        rows.append([
            _paragraph(key, styles["table_key"]),
            _paragraph(value, styles["body"]),
        ])

    table = Table(rows, colWidths=[55 * mm, 115 * mm], repeatRows=1)
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D9DEE8")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEF1F6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return table


def _findings(
    findings: Any,
    styles: dict[str, ParagraphStyle],
) -> list[Paragraph]:
    if not isinstance(findings, list) or not findings:
        return [_paragraph("No findings reported.", styles["body"])]

    result = []

    for finding in findings:
        result.append(
            Paragraph(
                f"• {escape(_text(finding))}",
                styles["body"],
            )
        )
        result.append(Spacer(1, 2))

    return result


def _url_table(
    findings: Any,
    styles: dict[str, ParagraphStyle],
) -> Table:
    rows = [[
        _paragraph("URL", styles["table_header"]),
        _paragraph("Domain", styles["table_header"]),
        _paragraph("Malicious", styles["table_header"]),
        _paragraph("Lookalike", styles["table_header"]),
        _paragraph("Reputation", styles["table_header"]),
    ]]

    if isinstance(findings, list):
        for item in findings:
            if not isinstance(item, dict):
                item = {"url": item}

            rows.append([
                _paragraph(item.get("url"), styles["body"]),
                _paragraph(item.get("domain"), styles["body"]),
                _paragraph(
                    "Yes" if item.get("is_malicious") is True
                    else "No" if item.get("is_malicious") is False
                    else "N/A",
                    styles["body"],
                ),
                _paragraph(
                    "Yes" if item.get("is_lookalike_domain") is True
                    else "No" if item.get("is_lookalike_domain") is False
                    else "N/A",
                    styles["body"],
                ),
                _paragraph(item.get("reputation"), styles["body"]),
            ])

    if len(rows) == 1:
        rows.append([
            _paragraph("No URLs detected.", styles["body"]),
            "", "", "", "",
        ])

    table = Table(
        rows,
        colWidths=[58 * mm, 38 * mm, 22 * mm, 22 * mm, 30 * mm],
        repeatRows=1,
    )
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D9DEE8")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEF1F6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


def _attachment_table(
    findings: Any,
    styles: dict[str, ParagraphStyle],
) -> Table:
    rows = [[
        _paragraph("Filename", styles["table_header"]),
        _paragraph("Type", styles["table_header"]),
        _paragraph("SHA-256", styles["table_header"]),
        _paragraph("Flagged", styles["table_header"]),
        _paragraph("Verdict", styles["table_header"]),
    ]]

    if isinstance(findings, list):
        for item in findings:
            if not isinstance(item, dict):
                item = {"filename": item}

            rows.append([
                _paragraph(item.get("filename"), styles["body"]),
                _paragraph(
                    item.get("file_type")
                    or item.get("content_type"),
                    styles["body"],
                ),
                _paragraph(
                    item.get("file_hash_sha256")
                    or item.get("sha256")
                    or item.get("hash"),
                    styles["small"],
                ),
                _paragraph(
                    "Yes"
                    if item.get("hash_reputation_flagged") is True
                    else "No"
                    if item.get("hash_reputation_flagged") is False
                    else "N/A",
                    styles["body"],
                ),
                _paragraph(item.get("verdict"), styles["body"]),
            ])

    if len(rows) == 1:
        rows.append([
            _paragraph("No attachments detected.", styles["body"]),
            "", "", "", "",
        ])

    table = Table(
        rows,
        colWidths=[35 * mm, 27 * mm, 62 * mm, 20 * mm, 26 * mm],
        repeatRows=1,
    )
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D9DEE8")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEF1F6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


def _section_title(
    title: str,
    styles: dict[str, ParagraphStyle],
) -> Paragraph:
    return Paragraph(escape(title), styles["section"])


def _footer(canvas, doc) -> None:
    canvas.saveState()

    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#777777"))

    canvas.drawCentredString(
        A4[0] / 2,
        9 * mm,
        "TRINETRA AI | CONFIDENTIAL FORENSIC TECHNICAL REPORT",
    )

    canvas.drawRightString(
        A4[0] - 14 * mm,
        9 * mm,
        f"Page {doc.page}",
    )

    canvas.restoreState()


def _build_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()

    return {
        "title": ParagraphStyle(
            "TrinetraTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#172033"),
            alignment=TA_LEFT,
            spaceAfter=4,
        ),
        "subtitle": ParagraphStyle(
            "TrinetraSubtitle",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#475467"),
            spaceAfter=4,
        ),
        "section": ParagraphStyle(
            "TrinetraSection",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#172033"),
            spaceBefore=12,
            spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "TrinetraBody",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#172033"),
            spaceAfter=3,
        ),
        "small": ParagraphStyle(
            "TrinetraSmall",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=7,
            leading=9,
            textColor=colors.HexColor("#475467"),
        ),
        "table_header": ParagraphStyle(
            "TrinetraTableHeader",
            parent=base["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=9,
            textColor=colors.HexColor("#172033"),
        ),
        "table_key": ParagraphStyle(
            "TrinetraTableKey",
            parent=base["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=9,
            textColor=colors.HexColor("#172033"),
        ),
        "risk": ParagraphStyle(
            "TrinetraRisk",
            parent=base["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=24,
            leading=28,
            textColor=colors.HexColor("#172033"),
        ),
        "notice": ParagraphStyle(
            "TrinetraNotice",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#344054"),
        ),
    }


def generate_pdf_report(
    case_id: str,
    full_case_data: dict[str, Any],
) -> bytes:
    """
    Generate a court/police-ready forensic technical report.

    This function returns PDF bytes and does not write a PDF to disk.
    The API endpoint is responsible for streaming the returned bytes.
    """

    from io import BytesIO

    data = full_case_data or {}
    styles = _build_styles()

    risk_fusion = data.get("risk_fusion") or {}

    risk_score = (
        risk_fusion.get("risk_score")
        if isinstance(risk_fusion, dict)
        else None
    )
    if risk_score is None:
        risk_score = data.get("risk_score", 0)

    classification = (
        risk_fusion.get("classification")
        if isinstance(risk_fusion, dict)
        else None
    ) or data.get("classification", "Unknown")

    layer1 = data.get("layer1") or data.get("layer1_result") or {}
    layer2 = data.get("layer2") or data.get("layer2_result") or {}
    layer3 = data.get("layer3") or data.get("layer3_result") or {}

    header_analysis = data.get("header_analysis") or {}
    nlp_analysis = data.get("nlp_analysis") or {}
    geolocation = data.get("geolocation") or {}
    anonymization = (
        data.get("anonymization_intelligence")
        or geolocation.get("anonymization_intelligence")
        or {}
    )

    url_findings = data.get("url_findings") or []
    attachment_findings = data.get("attachment_findings") or []

    related_cases = (
        data.get("related_cases")
        or data.get("related_case_ids")
        or []
    )

    sender_email = data.get("sender_email", "")
    sender_domain = data.get("sender_domain", "")
    subject = data.get("subject", "")
    reply_to = data.get("reply_to", "")

    generated_at = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    buffer = BytesIO()

    doc = BaseDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=14 * mm,
        leftMargin=14 * mm,
        topMargin=14 * mm,
        bottomMargin=16 * mm,
        title=f"Trinetra Forensic Report - {case_id}",
        author="Trinetra AI",
        subject="Email forensic technical examination report",
    )

    from reportlab.platypus import Frame, PageTemplate

    frame = Frame(
        doc.leftMargin,
        doc.bottomMargin,
        doc.width,
        doc.height,
        id="normal",
    )

    doc.addPageTemplates([
        PageTemplate(
            id="trinetra",
            frames=[frame],
            onPage=_footer,
        )
    ])

    story = []

    # ------------------------------------------------------------------
    # COVER / CASE IDENTIFICATION
    # ------------------------------------------------------------------

    story.append(Paragraph("TRINETRA AI", styles["title"]))
    story.append(
        Paragraph(
            "Email Threat Detection and Forensic Intelligence",
            styles["subtitle"],
        )
    )

    case_table = Table(
        [
            [
                _paragraph("Case / Reference ID", styles["table_header"]),
                _paragraph(case_id, styles["body"]),
            ],
            [
                _paragraph("Report Type", styles["table_header"]),
                _paragraph(
                    "Forensic Technical Examination Report",
                    styles["body"],
                ),
            ],
            [
                _paragraph("Generated", styles["table_header"]),
                _paragraph(generated_at, styles["body"]),
            ],
            [
                _paragraph("Prepared By", styles["table_header"]),
                _paragraph(
                    "Trinetra AI forensic analysis system",
                    styles["body"],
                ),
            ],
        ],
        colWidths=[50 * mm, 120 * mm],
    )

    case_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D9DEE8")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EEF1F6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))

    story.append(case_table)
    story.append(Spacer(1, 8))

    story.append(
        Paragraph(
            "<b>Purpose:</b> This report records technical findings "
            "generated from the supplied email artifact and associated "
            "analysis evidence. It is intended to assist investigators, "
            "law-enforcement personnel and legal professionals.",
            styles["body"],
        )
    )

    story.append(
        Paragraph(
            "<b>Important:</b> This is a technical forensic report, "
            "not a judicial finding of guilt, identity or attribution. "
            "Final legal characterization and evidentiary weight are "
            "determined by the competent investigating authority and court.",
            styles["notice"],
        )
    )

    # ------------------------------------------------------------------
    # LEGAL / EVIDENTIARY BASIS
    # ------------------------------------------------------------------

    story.append(_section_title(
        "Legal and Evidentiary Framework",
        styles,
    ))

    legal_rows = [
        [
            _paragraph("Framework", styles["table_header"]),
            _paragraph("Application to this report", styles["table_header"]),
        ],
        [
            _paragraph(
                "Bharatiya Sakshya Adhiniyam, 2023 - Sections 61 to 63",
                styles["table_key"],
            ),
            _paragraph(
                "Electronic or digital records are recognized as evidence "
                "subject to the statutory requirements. Section 63 addresses "
                "admissibility of electronic records and the certificate "
                "requirements for computer output.",
                styles["body"],
            ),
        ],
        [
            _paragraph(
                "Information Technology Act, 2000",
                styles["table_key"],
            ),
            _paragraph(
                "Potentially relevant where the investigated conduct "
                "satisfies the elements of an applicable provision, "
                "including Sections 43, 66, 66C or 66D. The exact offence "
                "must be determined from the facts and by the investigating "
                "authority; this report does not automatically charge an offence.",
                styles["body"],
            ),
        ],
        [
            _paragraph(
                "Other applicable criminal law",
                styles["table_key"],
            ),
            _paragraph(
                "The investigating authority may identify applicable "
                "provisions of the Bharatiya Nyaya Sanhita, 2023 or other "
                "special legislation based on the facts of the case.",
                styles["body"],
            ),
        ],
    ]

    legal_table = Table(
        legal_rows,
        colWidths=[55 * mm, 115 * mm],
        repeatRows=1,
    )

    legal_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D9DEE8")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEF1F6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))

    story.append(legal_table)

    # ------------------------------------------------------------------
    # RISK SUMMARY
    # ------------------------------------------------------------------

    story.append(_section_title(
        "Executive Risk Summary",
        styles,
    ))

    risk_table = Table(
        [
            [
                _paragraph("Risk Score", styles["table_header"]),
                _paragraph("Classification", styles["table_header"]),
            ],
            [
                Paragraph(
                    f"{escape(_text(risk_score, '0'))} / 100",
                    styles["risk"],
                ),
                Paragraph(
                    escape(_text(classification)),
                    styles["risk"],
                ),
            ],
        ],
        colWidths=[85 * mm, 85 * mm],
    )

    risk_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.6, colors.HexColor("#B8C0CC")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEF1F6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))

    story.append(risk_table)

    # ------------------------------------------------------------------
    # EMAIL IDENTIFICATION
    # ------------------------------------------------------------------

    story.append(_section_title(
        "Email Identification",
        styles,
    ))

    story.append(_dict_table(
        {
            "Sender": sender_email,
            "Sender Domain": sender_domain,
            "Reply-To": reply_to,
            "Subject": subject,
        },
        styles,
    ))

    # ------------------------------------------------------------------
    # LAYERED ANALYSIS
    # ------------------------------------------------------------------

    story.append(_section_title(
        "Layered Forensic Analysis",
        styles,
    ))

    story.append(_dict_table(
        {
            "Layer 1 - Header Forensics": layer1.get("layer1_score"),
            "Layer 2 - Threat Intelligence": layer2.get("layer2_score"),
            "Layer 3 - AI Reasoning Confidence": layer3.get("confidence"),
        },
        styles,
    ))

    story.append(_section_title(
        "Header Findings",
        styles,
    ))
    story.extend(_findings(layer1.get("findings"), styles))

    story.append(_section_title(
        "Header Analysis",
        styles,
    ))
    story.append(_dict_table(header_analysis, styles))

    story.append(_section_title(
        "NLP Analysis",
        styles,
    ))
    story.append(_dict_table(nlp_analysis, styles))

    story.append(_section_title(
        "AI Forensic Reasoning",
        styles,
    ))

    reasoning = (
        layer3.get("reasoning")
        or layer3.get("model_reasoning")
        or nlp_analysis.get("model_reasoning")
        or "No AI reasoning available."
    )

    story.append(
        Paragraph(
            escape(_text(reasoning)).replace("\n", "<br/>"),
            styles["body"],
        )
    )

    story.append(
        Paragraph(
            f"<b>Recommended Action:</b> "
            f"{escape(_text(layer3.get('recommended_action') or layer3.get('action')))}",
            styles["body"],
        )
    )

    # ------------------------------------------------------------------
    # URL / ATTACHMENT INTELLIGENCE
    # ------------------------------------------------------------------

    story.append(_section_title(
        "URL Intelligence",
        styles,
    ))
    story.append(_url_table(url_findings, styles))

    story.append(_section_title(
        "Attachment Intelligence",
        styles,
    ))
    story.append(_attachment_table(attachment_findings, styles))

    # ------------------------------------------------------------------
    # ORIGIN / GEOLOCATION
    # ------------------------------------------------------------------

    story.append(_section_title(
        "Geolocation and Origin Intelligence",
        styles,
    ))
    story.append(_dict_table(geolocation, styles))

    story.append(
        Paragraph(
            "<b>Interpretation:</b> Geolocation identifies an approximate "
            "location associated with observable network infrastructure. "
            "It does not establish the physical location or identity of "
            "the person who sent the email.",
            styles["notice"],
        )
    )

    story.append(_section_title(
        "Anonymization Intelligence",
        styles,
    ))
    story.append(_dict_table(anonymization, styles))

    # ------------------------------------------------------------------
    # CORRELATION / RISK FUSION
    # ------------------------------------------------------------------

    story.append(_section_title(
        "Historical Correlation",
        styles,
    ))

    if isinstance(related_cases, list) and related_cases:
        for case in related_cases:
            story.append(
                Paragraph(
                    f"• {escape(_text(case))}",
                    styles["body"],
                )
            )
    else:
        story.append(
            Paragraph(
                "No related historical cases were returned.",
                styles["body"],
            )
        )

    story.append(_section_title(
        "Risk Fusion Evidence",
        styles,
    ))
    story.append(_dict_table(risk_fusion, styles))

    # ------------------------------------------------------------------
    # FORENSIC INTEGRITY / CHAIN OF CUSTODY
    # ------------------------------------------------------------------

    story.append(PageBreak())

    story.append(_section_title(
        "Digital Evidence Integrity",
        styles,
    ))

    integrity = {}

    for key in (
        "case_id",
        "raw_sha256",
        "artifact_sha256",
        "email_sha256",
        "source_filename",
        "source_type",
        "chain_of_custody",
        "received_at",
        "analysis_started_at",
        "analysis_completed_at",
    ):
        if key in data:
            integrity[key] = data[key]

    if not integrity:
        integrity = {
            "Case ID": case_id,
            "Artifact integrity data": (
                "Not supplied by the analysis pipeline."
            ),
        }

    story.append(_dict_table(integrity, styles))

    story.append(
        Paragraph(
            "<b>Preservation recommendation:</b> retain the original "
            "email artifact in its original form, preserve its cryptographic "
            "hash, document every transfer or handling event, and retain the "
            "original artifact separately from derived analysis outputs.",
            styles["body"],
        )
    )

    # ------------------------------------------------------------------
    # BSA SECTION 63 CERTIFICATE SUPPORT
    # ------------------------------------------------------------------

    story.append(_section_title(
        "Electronic Record Certificate Support - BSA Section 63",
        styles,
    ))

    story.append(
        Paragraph(
            "This section is a technical certificate-support template. "
            "It is not a substitute for the statutory certificate that must "
            "be completed and signed by the person(s) legally competent to "
            "certify the electronic record under the applicable procedure.",
            styles["notice"],
        )
    )

    certificate_data = {
        "Case / Reference ID": case_id,
        "Electronic record identified": (
            data.get("source_filename")
            or data.get("artifact_name")
            or "Email artifact supplied for examination"
        ),
        "Record hash": (
            data.get("raw_sha256")
            or data.get("artifact_sha256")
            or data.get("email_sha256")
            or "Not supplied"
        ),
        "System used for processing": "Trinetra AI forensic analysis system",
        "Purpose of processing": (
            "Email forensic examination, threat detection, correlation "
            "and generation of derived technical findings."
        ),
        "Integrity statement": (
            "Derived report output should be verified against the preserved "
            "original artifact and recorded hash."
        ),
    }

    story.append(_dict_table(certificate_data, styles))

    story.append(Spacer(1, 8))
    story.append(
        Paragraph(
            "<b>Certification fields to be completed by the competent "
            "certifying person:</b>",
            styles["body"],
        )
    )

    signature_rows = [
        ["Name:", ""],
        ["Designation / Role:", ""],
        ["Organisation:", ""],
        ["Device / System particulars:", ""],
        ["Date and time:", ""],
        ["Signature:", ""],
        ["Seal / Official reference:", ""],
    ]

    signature_table = Table(
        signature_rows,
        colWidths=[55 * mm, 115 * mm],
        rowHeights=[10 * mm] * len(signature_rows),
    )

    signature_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B8C0CC")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
    ]))

    story.append(signature_table)

    # ------------------------------------------------------------------
    # LIMITATIONS
    # ------------------------------------------------------------------

    story.append(_section_title(
        "Limitations and Investigator Notes",
        styles,
    ))

    limitations = [
        "A risk score is an analytical indicator and is not a legal conclusion.",
        "AI-generated reasoning is supporting analysis and should be independently verified.",
        "Geolocation is approximate and does not establish a person's physical location.",
        "VPN, proxy and TOR indicators do not independently identify an attacker.",
        "Threat-intelligence results depend on the availability and accuracy of external sources.",
        "Historical correlation indicates technical similarity; it does not by itself prove common authorship.",
        "The original email artifact and its cryptographic hash should be preserved separately.",
        "The investigating authority and court determine the legal relevance and evidentiary weight of the findings.",
    ]

    story.extend(_findings(limitations, styles))

    story.append(Spacer(1, 8))
    story.append(
        Paragraph(
            "End of Report",
            ParagraphStyle(
                "End",
                parent=styles["body"],
                alignment=TA_CENTER,
                fontName="Helvetica-Bold",
                fontSize=8,
            ),
        )
    )

    doc.build(story)

    pdf_bytes = buffer.getvalue()

    if not pdf_bytes:
        raise RuntimeError("ReportLab returned empty PDF data.")

    if not pdf_bytes.startswith(b"%PDF"):
        raise RuntimeError("Generated output is not a valid PDF.")

    return pdf_bytes