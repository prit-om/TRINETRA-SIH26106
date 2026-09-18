from __future__ import annotations

from typing import Any


def _clean(value: Any) -> str | None:
    """Return a normalized non-empty string."""
    if value is None:
        return None

    value = str(value).strip()
    return value or None


def _add_node(
    nodes: list[dict[str, str]],
    edges: list[dict[str, str]],
    seen_nodes: set[str],
    case_node_id: str,
    node_type: str,
    value: Any,
    relationship: str,
) -> str | None:
    """Add a node and connect it to the case."""
    value = _clean(value)
    if not value:
        return None

    node_id = f"{node_type}:{value}"

    if node_id not in seen_nodes:
        nodes.append(
            {
                "id": node_id,
                "type": node_type,
                "label": value,
            }
        )
        seen_nodes.add(node_id)

    edge = {
        "source": case_node_id,
        "target": node_id,
        "relationship": relationship,
    }

    if edge not in edges:
        edges.append(edge)

    return node_id


def _unique_nodes(nodes: list[dict[str, str]]) -> list[dict[str, str]]:
    """Remove duplicate nodes while preserving order."""
    result = []
    seen = set()

    for node in nodes:
        node_id = node.get("id")
        if node_id and node_id not in seen:
            result.append(node)
            seen.add(node_id)

    return result


def _unique_edges(edges: list[dict[str, str]]) -> list[dict[str, str]]:
    """Remove duplicate relationships while preserving order."""
    result = []
    seen = set()

    for edge in edges:
        key = (
            edge.get("source"),
            edge.get("target"),
            edge.get("relationship"),
        )

        if key not in seen:
            result.append(edge)
            seen.add(key)

    return result


def build_ioc_graph(
    case_id: str,
    sender_email: str | None = None,
    sender_domain: str | None = None,
    geolocation: dict[str, Any] | None = None,
    url_findings: list[dict[str, Any]] | None = None,
    attachment_findings: list[dict[str, Any]] | None = None,
    client_timezone: str | None = None,
) -> dict[str, Any]:
    """
    Build the canonical IOC graph used by both the frontend and Neo4j.

    The graph contains:
        Case -> Sender
        Case -> Domain
        Case -> Origin IP
        Case -> Client Timezone
        Case -> URL Domain
        Case -> Attachment Hash

    This function does not claim attacker attribution.
    Historical correlation is performed by the Neo4j persistence layer.
    """
    case_id = _clean(case_id) or "unknown"

    case_node_id = f"case:{case_id}"

    nodes = [
        {
            "id": case_node_id,
            "type": "case",
            "label": case_id,
        }
    ]
    edges: list[dict[str, str]] = []
    seen_nodes = {case_node_id}

    sender_email = _clean(sender_email)
    sender_domain = _clean(sender_domain)

    if sender_email:
        _add_node(
            nodes,
            edges,
            seen_nodes,
            case_node_id,
            "sender",
            sender_email,
            "SENT_BY",
        )

    if sender_domain:
        _add_node(
            nodes,
            edges,
            seen_nodes,
            case_node_id,
            "domain",
            sender_domain,
            "USES_DOMAIN",
        )

    geolocation = geolocation or {}

    origin_ip = _clean(
        geolocation.get("earliest_external_ip")
        or geolocation.get("origin_ip")
        or geolocation.get("ip")
    )

    if origin_ip:
        _add_node(
            nodes,
            edges,
            seen_nodes,
            case_node_id,
            "origin_ip",
            origin_ip,
            "EXITED_VIA",
        )

    timezone = _clean(
        client_timezone
        or geolocation.get("client_timezone")
        or geolocation.get("timezone")
        or geolocation.get("offset")
    )

    if timezone:
        _add_node(
            nodes,
            edges,
            seen_nodes,
            case_node_id,
            "client_timezone",
            timezone,
            "ORIGINATED_IN_TIMEZONE",
        )

    for finding in url_findings or []:
        if not isinstance(finding, dict):
            finding = {"domain": finding}

        domain = _clean(finding.get("domain"))
        if domain:
            _add_node(
                nodes,
                edges,
                seen_nodes,
                case_node_id,
                "domain",
                domain,
                "CONTAINS_URL_DOMAIN",
            )

    for finding in attachment_findings or []:
        if not isinstance(finding, dict):
            finding = {"sha256": finding}

        sha256 = _clean(
            finding.get("file_hash_sha256")
            or finding.get("sha256")
            or finding.get("hash")
        )

        if sha256:
            _add_node(
                nodes,
                edges,
                seen_nodes,
                case_node_id,
                "attachment_hash",
                sha256,
                "CONTAINS_ATTACHMENT",
            )

    nodes = _unique_nodes(nodes)
    edges = _unique_edges(edges)

    return {
        "case_id": case_id,
        "nodes": nodes,
        "edges": edges,
        "neo4j_connected": False,
        "campaign_confidence": 0,
        "correlation": {
            "matched": False,
            "attacker_cluster_id": None,
            "confidence": 0,
            "signals": [],
        },
    }


def _unique(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Backward-compatible node deduplication helper."""
    return _unique_nodes(items)
