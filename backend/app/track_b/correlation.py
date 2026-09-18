

import logging

log = logging.getLogger(__name__)


def find_related_cases(current_case_indicators: dict, db_connection) -> list:
    if db_connection is None:
        return []

    sender_domain = (current_case_indicators.get("sender_domain") or "").strip().lower()
    ip = (current_case_indicators.get("earliest_external_ip") or "").strip()
    url_domains = [d for d in (current_case_indicators.get("url_domains") or []) if d]
    hashes = [h for h in (current_case_indicators.get("attachment_hashes") or []) if h]

    conditions = []
    params = []

    if sender_domain:
        conditions.append("c.sender_email LIKE ?")
        params.append(f"%@{sender_domain}")

    if ip:
        conditions.append(
            "EXISTS (SELECT 1 FROM geolocation g WHERE g.case_id = c.case_id AND g.earliest_external_ip = ?)"
        )
        params.append(ip)

    if url_domains:
        placeholders = ",".join("?" * len(url_domains))
        conditions.append(
            f"EXISTS (SELECT 1 FROM url_findings u WHERE u.case_id = c.case_id AND u.domain IN ({placeholders}))"
        )
        params.extend(url_domains)

    if hashes:
        placeholders = ",".join("?" * len(hashes))
        conditions.append(
            f"EXISTS (SELECT 1 FROM attachment_findings a WHERE a.case_id = c.case_id AND a.file_hash_sha256 IN ({placeholders}))"
        )
        params.extend(hashes)

    if not conditions:
        return []

    query = "SELECT DISTINCT c.case_id FROM cases c WHERE " + " OR ".join(conditions)

    try:
        cur = db_connection.cursor()
        cur.execute(query, params)
        return [str(r[0]) for r in cur.fetchall() if r and r[0] is not None]
    except Exception as e:
        log.warning("Case correlation query failed: %s", e)
        return []