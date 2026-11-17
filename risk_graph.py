import hashlib
import re
from typing import Any


def _confidence(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return None
    if not 0 <= numeric <= 100:
        return None
    return numeric / 100


def _type(value: Any) -> str:
    normalized = str(value or "observable").strip().casefold().replace("_", "-")
    return {
        "stixfile": "file",
        "x-opencti-event": "event",
        "x-opencti-asset": "asset",
    }.get(normalized, normalized)


def _entity_node(
    entity: dict,
    *,
    acquired_at: Any,
    provenance: Any = None,
) -> dict | None:
    node_id = entity.get("id")
    node_type = entity.get("entity_type") or entity.get("type")
    if not node_id or not node_type:
        return None
    normalized_type = _type(node_type)
    observable_value = (
        entity.get("observable_value")
        or entity.get("value")
    )
    return {
        "id": str(node_id),
        "type": normalized_type,
        "canonical_id": str(
            observable_value
            if normalized_type in {
                "observable", "ipv4-addr", "ipv6-addr", "domain-name", "url", "file"
            } and observable_value
            else entity.get("external_id") or node_id
        ),
        "source": "opencti",
        "provenance": str(
            provenance or entity.get("source") or entity.get("created_by") or "opencti"
        ),
        "acquired_at": acquired_at,
        "updated_at": entity.get("modified") or entity.get("created"),
        "confidence": _confidence(entity.get("confidence")),
        "valid_from": entity.get("valid_from"),
        "valid_until": entity.get("valid_until") or entity.get("stop_time"),
        "revoked": entity.get("revoked", False),
        "attributes": {
            key: entity[key]
            for key in ("pattern", "kill_chain_phases", "confidence", "name", "value")
            if entity.get(key) is not None
        },
    }


def build_event_opencti_graph(enrichment: Any, event_id: str) -> dict | None:
    if not isinstance(enrichment, dict):
        return None
    observables = enrichment.get("observables")
    if not isinstance(observables, list):
        return None

    nodes: list[dict] = [{
        "id": f"alert:{event_id}",
        "type": "alert",
        "canonical_id": str(event_id),
        "source": "event",
        "provenance": "analysis_log",
    }]
    edges: list[dict] = []
    aliases: dict[str, str] = {}
    graph_inputs: list[str] = []

    for observable_index, entry in enumerate(observables):
        if not isinstance(entry, dict):
            continue
        context = entry.get("opencti")
        if not isinstance(context, dict):
            continue
        acquired_at = context.get("acquired_at")
        entry_type = _type(entry.get("entity_type"))
        entry_value = str(entry.get("value") or "").strip()
        if not entry_value:
            continue

        observable_id = f"event-ioc:{entry_type}:{entry_value.casefold()}"
        nodes.append({
            "id": observable_id,
            "type": entry_type,
            "canonical_id": entry_value,
            "source": "event",
            "provenance": "analysis_log",
        })
        edges.append({
            "id": f"event-observes:{observable_index}",
            "type": "observes",
            "from": f"alert:{event_id}",
            "to": observable_id,
            "source": "event",
            "provenance": "analysis_log",
        })

        observable = context.get("observable")
        if isinstance(observable, dict) and observable.get("id"):
            aliases[str(observable["id"])] = observable_id
            graph_inputs.append(str(observable["id"]))

        indicators = context.get("indicators")
        if not isinstance(indicators, list):
            indicators = []
        for indicator in indicators:
            if not isinstance(indicator, dict):
                continue
            node = _entity_node(
                indicator,
                acquired_at=acquired_at,
                provenance=indicator.get("source") or indicator.get("created_by"),
            )
            if node is None:
                continue
            nodes.append(node)
            aliases[str(indicator["id"])] = str(indicator["id"])
            graph_inputs.append(str(indicator["id"]))

            pattern = indicator.get("pattern")
            related_observables = indicator.get("observables")
            relation_matches = False
            if isinstance(pattern, str):
                relation_matches = bool(re.search(
                    rf"""['"]{re.escape(entry_value)}['"]""",
                    pattern,
                    re.IGNORECASE,
                ))
            if isinstance(related_observables, list):
                relation_matches = relation_matches or any(
                    isinstance(item, dict)
                    and str(item.get("observable_value") or item.get("value") or "").casefold()
                    == entry_value.casefold()
                    for item in related_observables
                )
            if relation_matches:
                edges.append({
                    "id": f"opencti-match:{indicator['id']}:{observable_id}",
                    "type": "matches_observable",
                    "from": observable_id,
                    "to": str(indicator["id"]),
                    "source": "opencti",
                    "provenance": node["provenance"],
                    "acquired_at": acquired_at,
                    "updated_at": node["updated_at"],
                    "confidence": node["confidence"],
                    "valid_from": node["valid_from"],
                    "valid_until": node["valid_until"],
                    "revoked": node["revoked"],
                })

        related_entities = context.get("related_entities")
        if isinstance(related_entities, list):
            for entity in related_entities:
                if not isinstance(entity, dict):
                    continue
                node = _entity_node(entity, acquired_at=acquired_at)
                if node is not None:
                    nodes.append(node)
                    aliases[str(entity["id"])] = str(entity["id"])
                    graph_inputs.append(str(entity["id"]))

        relationships = context.get("relationships")
        if isinstance(relationships, list):
            for relation_index, relation in enumerate(relationships):
                if not isinstance(relation, dict):
                    continue
                endpoints: dict[str, str] = {}
                for direction in ("from", "to"):
                    endpoint = relation.get(direction)
                    if not isinstance(endpoint, dict) or not endpoint.get("id"):
                        continue
                    endpoint_id = str(endpoint["id"])
                    resolved_id = aliases.get(endpoint_id, endpoint_id)
                    endpoints[direction] = resolved_id
                    if resolved_id == endpoint_id and not any(
                        item.get("id") == endpoint_id for item in nodes
                    ):
                        node = _entity_node(endpoint, acquired_at=acquired_at)
                        if node is not None:
                            nodes.append(node)
                            aliases[endpoint_id] = endpoint_id
                if len(endpoints) != 2:
                    continue
                relation_id = str(
                    relation.get("id")
                    or f"opencti-relation:{observable_index}:{relation_index}"
                )
                edges.append({
                    "id": relation_id,
                    "type": str(relation.get("relationship_type") or ""),
                    "from": endpoints["from"],
                    "to": endpoints["to"],
                    "source": "opencti",
                    "provenance": str(relation.get("source") or "opencti"),
                    "acquired_at": acquired_at,
                    "updated_at": relation.get("modified") or relation.get("created"),
                    "confidence": _confidence(relation.get("confidence")),
                    "valid_from": relation.get("start_time"),
                    "valid_until": relation.get("stop_time"),
                    "revoked": relation.get("revoked", False),
                })

    if len(nodes) == 1:
        return None

    snapshot_seed = "|".join(sorted(graph_inputs))
    snapshot_seed += "|" + "|".join(
        str(node.get("acquired_at") or "") for node in nodes if node["source"] == "opencti"
    )
    snapshot_id = "opencti:" + hashlib.sha256(snapshot_seed.encode()).hexdigest()[:16]
    return {
        "snapshot_id": snapshot_id,
        "source": "opencti",
        "nodes": nodes,
        "edges": edges,
    }
