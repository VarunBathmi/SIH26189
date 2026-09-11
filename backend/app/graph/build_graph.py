import datetime
import logging
from typing import List, Dict, Any, Optional
from app.graph.neo4j_connection import get_neo4j_driver, is_neo4j_available
from app.graph.networkx_engine import (
    upsert_networkx_node,
    upsert_networkx_edge,
    export_networkx_graph_json,
    reset_networkx_graph
)

logger = logging.getLogger(__name__)

# Valid specialized node labels in our schema
SPECIALIZED_LABELS = {
    "Person", "Location", "Case", "Device", "File", "IPAddress",
    "Organization", "Landmark", "Bank", "Account", "Event",
    "Transaction", "Call", "SurveillanceEvent", "Entity", "Phone", "Vehicle"
}

def clean_label(label: str) -> str:
    """Ensure label name conforms to alphanumeric Neo4j label conventions."""
    if not label:
        return "Entity"
    cleaned = "".join(c for c in label if c.isalnum() or c == "_")
    if cleaned.lower() in ("person", "suspect", "individual"):
        return "Person"
    elif cleaned.lower() in ("location", "gpe", "fac", "place"):
        return "Location"
    elif cleaned.lower() in ("organization", "org", "company", "gang"):
        return "Organization"
    elif cleaned.lower() in ("phone", "mobile", "number"):
        return "Phone"
    elif cleaned.lower() in ("vehicle", "car", "plate"):
        return "Vehicle"
    elif cleaned.lower() in ("case", "investigation"):
        return "Case"
    elif cleaned:
        return cleaned.capitalize()
    return "Entity"

def write_graph(
    cid: str,
    records: List[Dict[str, Any]],
    is_rebuild: bool = False
) -> Dict[str, Any]:
    """
    Ingest or upsert graph records with strict case isolation.
    Supports both generic Entity nodes and specialized investigation labels.
    Synchronizes simultaneously with Neo4j and NetworkX.
    """
    driver = get_neo4j_driver()
    nodes_added = []
    edges_added = []

    # 1. Update in-memory NetworkX graph
    if is_rebuild:
        reset_networkx_graph(cid)

    for r in records:
        src = str(r["source"])
        tgt = str(r["target"])
        src_type = clean_label(r.get("source_type", "Entity"))
        tgt_type = clean_label(r.get("target_type", "Entity"))
        rel = r.get("relation") or r.get("type") or "RELATED"
        h = str(r.get("artifact_hash", r.get("hash", "")))
        ts = str(r.get("timestamp", ""))
        w = float(r.get("weight", 1.0))
        props = r.get("properties", {})

        # NetworkX sync
        upsert_networkx_node(cid, src, node_type=src_type, label=r.get("source_label", src), properties=props)
        upsert_networkx_node(cid, tgt, node_type=tgt_type, label=r.get("target_label", tgt), properties=props)
        upsert_networkx_edge(cid, src, tgt, relation=rel, weight=w, timestamp=ts, artifact_hash=h, properties=props)

        nodes_added.extend([
            {"id": src, "type": src_type, "label": r.get("source_label", src)},
            {"id": tgt, "type": tgt_type, "label": r.get("target_label", tgt)}
        ])
        edges_added.append({
            "source": src,
            "target": tgt,
            "type": rel,
            "relation": rel,
            "weight": w,
            "timestamp": ts,
            "hash": h,
            "properties": props
        })

    # 2. Update Neo4j if available
    if driver and is_neo4j_available():
        try:
            with driver.session() as s:
                if is_rebuild:
                    # Explicit case rebuild
                    s.run("MATCH (n {case_id: $cid}) DETACH DELETE n", cid=cid)

                for r in records:
                    src = str(r["source"])
                    tgt = str(r["target"])
                    src_type = clean_label(r.get("source_type", "Entity"))
                    tgt_type = clean_label(r.get("target_type", "Entity"))
                    rel = r.get("relation") or r.get("type") or "RELATED"
                    h = str(r.get("artifact_hash", r.get("hash", "")))
                    ts = str(r.get("timestamp", ""))
                    w = float(r.get("weight", 1.0))

                    # Clean relation type for Cypher
                    clean_rel = "".join(c for c in rel if c.isalnum() or c == "_").upper() or "RELATED"

                    # Dynamic parameterized Cypher with multi-label support
                    cypher_query = f"""
                        MERGE (a:Entity {{case_id: $cid, id: $a}})
                        SET a:{src_type}, a.type = $at, a.label = $a_label

                        MERGE (b:Entity {{case_id: $cid, id: $b}})
                        SET b:{tgt_type}, b.type = $bt, b.label = $b_label

                        MERGE (a)-[x:{clean_rel} {{case_id: $cid, source_id: $a, target_id: $b}}]->(b)
                        SET x.relation = $rel,
                            x.timestamp = $ts,
                            x.weight = $w,
                            x.hash = $h,
                            x.artifact_hash = $h
                    """

                    s.run(
                        cypher_query,
                        cid=cid,
                        a=src,
                        b=tgt,
                        at=src_type,
                        bt=tgt_type,
                        a_label=r.get("source_label", src),
                        b_label=r.get("target_label", tgt),
                        rel=rel,
                        h=h,
                        ts=ts,
                        w=w
                    )
        except Exception as e:
            logger.error(f"Error executing Neo4j Cypher upsert: {e}")

    # Deduplicate delta
    unique_nodes = {n["id"]: n for n in nodes_added}.values()

    return {
        "case_id": cid,
        "nodes_added": list(unique_nodes),
        "edges_added": edges_added
    }

def get_case_graph(cid: str) -> Dict[str, Any]:
    """
    Retrieve full case graph formatted for frontend visualization (Cytoscape / Vis.js / D3).
    Queries Neo4j if available, or seamlessly returns from NetworkX.
    """
    driver = get_neo4j_driver()

    if driver and is_neo4j_available():
        try:
            with driver.session() as s:
                result = s.run("""
                    MATCH (n {case_id: $cid})
                    OPTIONAL MATCH (n)-[r]->(m {case_id: $cid})
                    RETURN
                        collect(DISTINCT {
                            id: COALESCE(n.id, n.hash_id, n.name),
                            type: COALESCE(n.type, labels(n)[0], "Entity"),
                            label: COALESCE(n.label, n.name, n.id, "Node")
                        }) AS nodes,
                        collect(DISTINCT CASE
                            WHEN m IS NULL THEN NULL
                            ELSE {
                                source: COALESCE(n.id, n.hash_id, n.name),
                                target: COALESCE(m.id, m.hash_id, m.name),
                                relation: COALESCE(r.relation, type(r), "RELATED"),
                                type: COALESCE(r.relation, type(r), "RELATED"),
                                timestamp: COALESCE(r.timestamp, ""),
                                weight: COALESCE(r.weight, 1.0),
                                hash: COALESCE(r.hash, r.artifact_hash, "")
                            }
                        END) AS links
                """, cid=cid).single()

                if result:
                    raw_nodes = result["nodes"] or []
                    raw_links = [x for x in (result["links"] or []) if x is not None]
                    
                    # Ensure node list contains all endpoints
                    node_map = {n["id"]: n for n in raw_nodes if n.get("id")}
                    for l in raw_links:
                        if l["source"] not in node_map:
                            node_map[l["source"]] = {"id": l["source"], "type": "Entity", "label": l["source"]}
                        if l["target"] not in node_map:
                            node_map[l["target"]] = {"id": l["target"], "type": "Entity", "label": l["target"]}

                    final_nodes = list(node_map.values())
                    return {
                        "case_id": cid,
                        "nodes": final_nodes,
                        "links": raw_links,
                        "edges": raw_links,
                        "metadata": {
                            "node_count": len(final_nodes),
                            "link_count": len(raw_links),
                            "engine": "Neo4j 5.20",
                            "generated_at": datetime.datetime.utcnow().isoformat()
                        }
                    }
        except Exception as e:
            logger.warning(f"Neo4j query failed ({e}), falling back to NetworkX.")

    # Fallback to NetworkX
    fallback_data = export_networkx_graph_json(cid)
    fallback_data["metadata"]["engine"] = "NetworkX Core"
    fallback_data["metadata"]["generated_at"] = datetime.datetime.utcnow().isoformat()
    return fallback_data
