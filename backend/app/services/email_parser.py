from __future__ import annotations

import html
import ipaddress
import re
from email import policy
from email.header import decode_header, make_header
from email.message import Message
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime


URL_RE = re.compile(
    r"(?i)\b(?:https?|ftp)://[^\s<>\"]+"
    r"|(?<!@)\b(?:www\.)[^\s<>\"]+"
)

IP_RE = re.compile(
    r"(?<![\w:])(?:"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"|[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){2,7}"
    r")(?![\w:])",
    re.IGNORECASE,
)

HTML_TAG_RE = re.compile(r"<[^>]+>")


def _decode_header_value(value: str | None) -> str:
    """Safely decode RFC-2047 encoded header values."""
    if not value:
        return ""

    try:
        return str(make_header(decode_header(str(value)))).strip()
    except Exception:
        return str(value).strip()


def _html_to_text(value: str) -> str:
    """Convert HTML email content to readable plain text."""
    if not value:
        return ""

    value = re.sub(
        r"(?is)<(script|style).*?>.*?</\1>",
        " ",
        value,
    )

    value = HTML_TAG_RE.sub(" ", value)
    value = html.unescape(value)

    value = re.sub(r"[ \t\r\f\v]+", " ", value)
    value = re.sub(r"\n\s*\n+", "\n\n", value)

    return value.strip()


def _decode_payload(part: Message) -> str:
    """
    Decode a text MIME part safely.

    Handles declared charset and falls back to UTF-8 / latin-1
    instead of allowing a malformed charset to destroy parsing.
    """
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        return ""

    if payload is None:
        return ""

    charset = part.get_content_charset()

    candidates = []

    if charset:
        candidates.append(charset)

    candidates.extend(
        [
            "utf-8",
            "latin-1",
        ]
    )

    for encoding in candidates:
        try:
            return payload.decode(
                encoding,
                errors="replace",
            )
        except (LookupError, UnicodeError):
            continue

    return payload.decode(
        "utf-8",
        errors="replace",
    )


def _extract_body_text(message: Message) -> str:
    """
    Extract the best available human-readable body.

    Preference:
        text/plain > text/html

    Attachments are excluded.
    """
    plain_parts: list[str] = []
    html_parts: list[str] = []

    if message.is_multipart():
        parts = message.walk()
    else:
        parts = [message]

    for part in parts:
        if part.is_multipart():
            continue

        disposition = (
            part.get_content_disposition()
            or ""
        ).lower()

        if disposition == "attachment":
            continue

        content_type = (
            part.get_content_type()
            or ""
        ).lower()

        if content_type not in {
            "text/plain",
            "text/html",
        }:
            continue

        text = _decode_payload(part)

        if not text:
            continue

        if content_type == "text/plain":
            plain_parts.append(text.strip())

        elif content_type == "text/html":
            html_parts.append(text)

    plain_parts = [
        part
        for part in plain_parts
        if part
    ]

    if plain_parts:
        return "\n\n".join(
            plain_parts
        ).strip()

    if html_parts:
        return _html_to_text(
            "\n\n".join(html_parts)
        )

    return ""


def _extract_urls(body_text: str) -> list[str]:
    """Extract and deduplicate URLs from message body."""
    found: list[str] = []

    for match in URL_RE.finditer(
        body_text or ""
    ):
        url = match.group(0).rstrip(
            ".,;:!?)]}>\"'"
        )

        if url and url not in found:
            found.append(url)

    return found


def _valid_ip(candidate: str) -> bool:
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def _extract_received_header(
    value: str,
) -> dict | None:
    """
    Extract useful forensic information from one
    RFC Received header.

    Received headers are intentionally treated as
    semi-structured data because their syntax varies
    between mail systems.
    """
    if not value:
        return None

    from_match = re.search(
        r"(?i)\bfrom\s+(.+?)(?=\s+\bby\s+|\s*;|$)",
        value,
    )

    by_match = re.search(
        r"(?i)\bby\s+(.+?)(?=\s+\bwith\s+|\s+\bid\s+|\s*;|$)",
        value,
    )

    ips = [
        ip
        for ip in IP_RE.findall(value)
        if _valid_ip(ip)
    ]

    # A Received header without an IP is not useful
    # to the current relay-forensics contract.
    if not ips:
        return None

    timestamp = ""

    if ";" in value:
        date_part = value.rsplit(
            ";",
            1,
        )[1].strip()

        try:
            timestamp = parsedate_to_datetime(
                date_part
            ).isoformat()
        except Exception:
            timestamp = date_part

    return {
        "from": (
            from_match.group(1).strip()
            if from_match
            else ""
        ),
        "by": (
            by_match.group(1).strip()
            if by_match
            else ""
        ),
        "ip": ips[0],
        "timestamp": timestamp,
    }


def _parse_message(
    raw_email_bytes: bytes,
) -> Message:
    """
    Parse an email artifact using the standard Python
    email parser.

    defects='replace' prevents malformed MIME sections
    from causing the entire forensic analysis to fail.
    """
    try:
        return BytesParser(
            policy=policy.default,
        ).parsebytes(
            bytes(raw_email_bytes),
        )
    except Exception as exc:
        raise ValueError(
            f"Unable to parse email artifact: {exc}"
        ) from exc


def _has_meaningful_email_data(
    message: Message,
    body_text: str,
) -> bool:
    """
    Determine whether parsing produced meaningful
    email content.

    A completely empty parsed message should not
    silently enter the threat-analysis pipeline.
    """
    has_headers = any(
        message.get(header)
        for header in (
            "From",
            "To",
            "Subject",
            "Date",
            "Message-ID",
            "Received",
        )
    )

    has_body = bool(
        body_text.strip()
    )

    return has_headers or has_body


def parse_email(
    raw_email_bytes: bytes,
) -> dict:
    """
    Parse an .eml/RFC-5322 email artifact.

    Returns the normalized structure expected by
    Trinetra's downstream analysis pipeline.
    """
    if not isinstance(
        raw_email_bytes,
        (bytes, bytearray),
    ):
        raise ValueError(
            "raw_email_bytes must contain email bytes"
        )

    if not raw_email_bytes:
        raise ValueError(
            "raw_email_bytes must contain non-empty email bytes"
        )

    raw_bytes = bytes(
        raw_email_bytes
    )

    message = _parse_message(
        raw_bytes
    )

    # ---------------------------------------------------------
    # Headers
    # ---------------------------------------------------------

    from_header = _decode_header_value(
        message.get("From")
    )

    reply_to_header = _decode_header_value(
        message.get("Reply-To")
    )

    subject = _decode_header_value(
        message.get("Subject")
    )

    from_name, sender_email = parseaddr(
        from_header
    )

    _, reply_to = parseaddr(
        reply_to_header
    )

    # ---------------------------------------------------------
    # Body
    # ---------------------------------------------------------

    body_text = _extract_body_text(
        message
    )

    # ---------------------------------------------------------
    # Validate parse result
    # ---------------------------------------------------------

    if not _has_meaningful_email_data(
        message,
        body_text,
    ):
        raise ValueError(
            "Email artifact could not be parsed into "
            "meaningful headers or body content. "
            "Verify that the supplied artifact is a valid "
            "RFC-5322/.eml message."
        )

    # ---------------------------------------------------------
    # Received chain
    # ---------------------------------------------------------

    received_headers = message.get_all(
        "Received",
        [],
    )

    received_chain: list[dict] = []

    # RFC mail headers normally appear newest-first.
    # Reverse them so forensic analysis receives
    # earliest -> newest.
    for received in reversed(
        received_headers
    ):
        hop = _extract_received_header(
            str(received)
        )

        if hop:
            received_chain.append(
                hop
            )

    # ---------------------------------------------------------
    # Attachments
    # ---------------------------------------------------------

    attachments_found: list[dict] = []

    for part in message.walk():
        if part.is_multipart():
            continue

        filename = part.get_filename()

        disposition = (
            part.get_content_disposition()
            or ""
        ).lower()

        if not filename and disposition != "attachment":
            continue

        filename = _decode_header_value(
            filename
        )

        try:
            payload = part.get_payload(
                decode=True
            )
        except Exception:
            payload = None

        attachments_found.append(
            {
                "filename": filename,
                "file_bytes": payload or b"",
            }
        )

    # ---------------------------------------------------------
    # URLs
    # ---------------------------------------------------------

    urls_found = _extract_urls(
        body_text
    )

    # ---------------------------------------------------------
    # Normalized result
    # ---------------------------------------------------------

    return {
        "sender_email": sender_email,
        "sender_display_name": _decode_header_value(
            from_name
        ),
        "reply_to": reply_to,
        "subject": subject,
        "body_text": body_text,
        "urls_found": urls_found,
        "attachments_found": attachments_found,
        "received_chain": received_chain,
    }