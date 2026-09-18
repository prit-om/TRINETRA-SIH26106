from __future__ import annotations

import logging
import os
from typing import Any

log = logging.getLogger(__name__)


_NODE_LABELS = {
    "case": "Case",
    "sender": "Sender",
    "domain": "Domain",
    "origin_ip": "OriginIP",
    "client_timezone": "ClientTimezone",
    "attachment_hash": "AttachmentHash",
}


_RELATIONSHIP_TYPES = {
    "SENT_BY": "SENT_BY",
    "USES_DOMAIN": "USES_DOMAIN",
    "EXITED_VIA": "EXITED_VIA",
    "ORIGINATED_IN_TIMEZONE": "ORIGINATED_IN_TIMEZONE",
    "CONTAINS_URL_DOMAIN": "CONTAINS_URL_DOMAIN",
    "CONTAINS_ATTACHMENT": "CONTAINS_ATTACHMENT",
}


def _clean(value: Any) -> str | None:
    """Return a normalized non-empty string."""
    if value is None:
        return None

    value = str(value).strip()
    return value or None


def _safe_identifier(value: str) -> str:
    """Return a known-safe Neo4j label/type identifier."""
    if value not in _NODE_LABELS and value not in _RELATIONSHIP_TYPES:
        raise ValueError(f"Unsupported Neo4j identifier: {value}")
    return value


def _persist_node(session, node: dict[str, Any]) -> None:
    """Create/update one canonical graph node."""
    node_type = _clean(node.get("type"))
    node_id = _clean(node.get("id"))
    value = _clean(node.get("label"))

    if not node_type or not node_id or not value:
        return

    label = _NODE_LABELS.get(node_type)
    if not label:
        log.warning("Skipping unsupported graph node type: %s", node_type)
        return

    query = f"""
    MERGE (n:{label} {{id: $id}})
    SET n.type = $type,
        n.value = $value
    """

    session.run(
        query,
        id=node_id,
        type=node_type,
        value=value,
    )


def _persist_edge(session, edge: dict[str, Any]) -> None:
    """Create one relationship between already-created graph nodes."""
    source = _clean(edge.get("source"))
    target = _clean(edge.get("target"))
    relationship = _clean(edge.get("relationship"))

    if not source or not target or not relationship:
        return

    relationship = _safe_identifier(relationship)

    query = f"""
    MATCH (source {{id: $source}})
    MATCH (target {{id: $target}})
    MERGE (source)-[:{relationship}]->(target)
    """

    session.run(
        query,
        source=source,
        target=target,
    )


def _correlate_case(
    session,
    case_id: str,
    sender_email: str | None,
) -> dict[str, Any]:
    """
    Find historical cases sharing meaningful infrastructure.

    Correlation signals:
        - same sender email
        - same attachment hash
        - same URL/domain
        - same origin IP
        - same client timezone

    Timezone alone is treated as a weak signal.
    """
    query = """
    MATCH (current:Case {id: $case_id})

    OPTIONAL MATCH (current)-[:SENT_BY]->(sender:Sender)
    OPTIONAL MATCH (current)-[:EXITED_VIA]->(ip:OriginIP)
    OPTIONAL MATCH (current)-[:ORIGINATED_IN_TIMEZONE]->(tz:ClientTimezone)
    OPTIONAL MATCH (current)-[:CONTAINS_ATTACHMENT]->(hash:AttachmentHash)
    OPTIONAL MATCH (current)-[:CONTAINS_URL_DOMAIN]->(domain:Domain)

    OPTIONAL MATCH (previous:Case)
    WHERE previous.id <> current.id
      AND (
          (sender IS NOT NULL AND (previous)-[:SENT_BY]->(sender))
          OR
          (ip IS NOT NULL AND (previous)-[:EXITED_VIA]->(ip))
          OR
          (tz IS NOT NULL AND (previous)-[:ORIGINATED_IN_TIMEZONE]->(tz))
          OR
          (hash IS NOT NULL AND (previous)-[:CONTAINS_ATTACHMENT]->(hash))
          OR
          (domain IS NOT NULL AND (previous)-[:CONTAINS_URL_DOMAIN]->(domain))
      )

    RETURN DISTINCT previous.id AS related_case_id
    LIMIT 50
    """

    related = [
        record["related_case_id"]
        for record in session.run(query, case_id=case_id)
        if record.get("related_case_id")
    ]

    if not related:
        return {
            "matched": False,
            "attacker_cluster_id": None,
            "confidence": 0,
            "signals": [],
            "related_cases": [],
        }

    signals = []

    if sender_email:
        sender_match_query = """
        MATCH (current:Case {id: $case_id})-[:SENT_BY]->(sender:Sender)
        MATCH (previous:Case)-[:SENT_BY]->(sender)
        WHERE previous.id <> current.id
        RETURN count(previous) AS count
        """
        sender_match = session.run(
            sender_match_query,
            case_id=case_id,
        ).single()

        if sender_match and sender_match["count"] > 0:
            signals.append("same sender")

    cluster_id = f"CLUSTER-{case_id}"

    confidence = min(
        95,
        25 + 15 * len(signals) + min(30, 10 * len(related)),
    )

    return {
        "matched": True,
        "attacker_cluster_id": cluster_id,
        "confidence": confidence,
        "signals": signals,
        "related_cases": related,
    }


def persist_graph(graph: dict[str, Any], case_id: str) -> bool:
    """
    Persist the canonical IOC graph to Neo4j.

    Returns True only when the graph was successfully written.
    Returns False when Neo4j configuration or connectivity is unavailable.
    """
    uri = os.getenv("NEO4J_URI")
    user = os.getenv("NEO4J_USER")
    password = os.getenv("NEO4J_PASSWORD")

    if not (uri and user and password):
        log.warning("Neo4j configuration is missing.")
        return False

    driver = None

    try:
        from neo4j import GraphDatabase

        driver = GraphDatabase.driver(
            uri,
            auth=(user, password),
        )

        driver.verify_connectivity()

        with driver.session() as session:
            session.run(
                "MERGE (c:Case {id: $case_id})",
                case_id=case_id,
            )

            for node in graph.get("nodes", []):
                _persist_node(session, node)

            for edge in graph.get("edges", []):
                _persist_edge(session, edge)

            correlation = _correlate_case(
                session,
                case_id,
                _get_sender_email(graph),
            )

            graph["correlation"] = correlation
            graph["campaign_confidence"] = correlation["confidence"]
            graph["neo4j_connected"] = True

            _persist_correlation(session, case_id, correlation)

        return True

    except Exception as exc:
        log.warning("Neo4j unavailable or graph persistence failed: %s", exc)
        graph["neo4j_connected"] = False
        return False

    finally:
        if driver is not None:
            driver.close()


def _get_sender_email(graph: dict[str, Any]) -> str | None:
    """Extract sender email from the canonical graph."""
    for node in graph.get("nodes", []):
        if node.get("type") == "sender":
            return _clean(node.get("label"))
    return None


def _persist_correlation(
    session,
    case_id: str,
    correlation: dict[str, Any],
) -> None:
    """Persist a campaign cluster only when historical correlation exists."""
    cluster_id = correlation.get("attacker_cluster_id")

    if not cluster_id:
        return

    session.run(
        """
        MERGE (c:Campaign {cluster_id: $cluster_id})
        SET c.confidence = $confidence,
            c.signals = $signals
        WITH c
        MATCH (e:Case {id: $case_id})
        MERGE (e)-[:LINKED_ATTACKER_CLUSTER]->(c)
        """,
        cluster_id=cluster_id,
        confidence=correlation.get("confidence", 0),
        signals=correlation.get("signals", []),
        case_id=case_id,
    )