import os
import datetime
import logging
from typing import Dict, List, Any, Optional
from neo4j import GraphDatabase, Driver
from app.config import settings
from app.graph.neo4j_connection import get_neo4j_driver, is_neo4j_available
from app.graph.networkx_engine import (
    upsert_networkx_node,
    upsert_networkx_edge,
    export_networkx_graph_json,
    reset_networkx_graph,
    get_networkx_graph
)

logger = logging.getLogger(__name__)

class Neo4jGraphEngine:
    """
    Neo4j Graph Database Engine with strict case isolation (case_id property scoping).
    Provides synchronized persistence with Neo4j and in-memory NetworkX graph analytics.
    """

    def __init__(self, uri: Optional[str] = None, user: Optional[str] = None, password: Optional[str] = None):
        self.uri = uri or settings.NEO4J_URI
        self.user = user or settings.NEO4J_USER
        self.password = password or settings.NEO4J_PASSWORD
        self._driver: Optional[Driver] = None
        self._init_constraints()

    def get_driver(self) -> Optional[Driver]:
        """Retrieve active driver or create a new driver instance."""
        if self._driver is None:
            try:
                self._driver = get_neo4j_driver()
            except Exception as e:
                logger.warning(f"Could not connect to Neo4j at {self.uri}: {e}")
        return self._driver

    def _init_constraints(self):
        """Idempotently create required indexes and uniqueness constraints on startup."""
        driver = self.get_driver()
        if not driver or not is_neo4j_available():
            return

        try:
            with driver.session() as session:
                # Schema constraint: Entity uniqueness scoped to case_id
                session.run("""
                    CREATE CONSTRAINT entity_id_case IF NOT EXISTS
                    FOR (e:Entity) REQUIRE (e.entity_id, e.case_id) IS UNIQUE
                """)
                # Case constraint
                session.run("""
                    CREATE CONSTRAINT case_id_unique IF NOT EXISTS
                    FOR (c:Case) REQUIRE c.case_id IS UNIQUE
                """)
                logger.info("Neo4j schema constraints initialized successfully.")
        except Exception as e:
            logger.warning(f"Neo4j constraint creation notice: {e}")

    def load_case(self, case_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ingest and MERGE structured case entities and forensic artifacts into Neo4j
        and synchronize with the in-memory NetworkX engine.
        
        Guarantees strict case-level graph isolation via case_id scoping on every node and edge.
        """
        case_id = (case_data.get("case_id") or "CASE-IMPORT").strip()
        entities = case_data.get("entities", [])
        artifacts = case_data.get("artifacts", [])
        note = case_data.get("note", f"Investigation Case {case_id}")
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        nodes_added = []
        edges_added = []

        # 1. Synchronize to in-memory NetworkX graph
        reset_networkx_graph(case_id)

        # Upsert Case node
        upsert_networkx_node(
            case_id=case_id,
            node_id=case_id,
            node_type="Case",
            label=f"Case {case_id}",
            properties={"case_id": case_id, "note": note, "loaded_at": now_iso}
        )

        # Upsert Entity nodes
        for ent in entities:
            e_id = str(ent.get("entity_id") or ent.get("id") or ent.get("name") or "UNKNOWN")
            name = str(ent.get("name") or e_id)
            phone = str(ent.get("phone") or "")
            device_id = str(ent.get("device_id") or "")
            ip = str(ent.get("ip") or "")

            props = {
                "entity_id": e_id,
                "case_id": case_id,
                "name": name,
                "phone": phone,
                "device_id": device_id,
                "ip": ip
            }
            upsert_networkx_node(
                case_id=case_id,
                node_id=e_id,
                node_type="Entity",
                label=name,
                properties=props
            )
            # Link Case -> Entity
            upsert_networkx_edge(
                case_id=case_id,
                source=case_id,
                target=e_id,
                relation="HAS_ENTITY",
                weight=1.0,
                timestamp=now_iso,
                properties={"case_id": case_id}
            )
            nodes_added.append({"id": e_id, "name": name, "type": "Entity"})

        # Upsert Artifacts (Edges)
        for art in artifacts:
            r_type = (art.get("record_type") or art.get("type") or "related").lower()
            r_id = str(art.get("record_id") or "")
            ts = str(art.get("timestamp") or "")

            if r_type == "call":
                src = str(art.get("caller_id") or art.get("caller") or "UNKNOWN")
                tgt = str(art.get("callee_id") or art.get("callee") or "UNKNOWN")
                dur = int(art.get("duration_sec", 0))
                rel = "CALLED"
                props = {"record_id": r_id, "duration_sec": dur, "timestamp": ts, "case_id": case_id}
                upsert_networkx_edge(case_id, src, tgt, relation=rel, weight=1.0, timestamp=ts, properties=props)
                edges_added.append({"source": src, "target": tgt, "relation": rel, "properties": props})

            elif r_type in ("chat", "message"):
                src = str(art.get("sender_id") or art.get("sender") or "UNKNOWN")
                tgt = str(art.get("receiver_id") or art.get("receiver") or "UNKNOWN")
                platform = str(art.get("platform") or "Chat")
                rel = "MESSAGED"
                props = {"record_id": r_id, "platform": platform, "timestamp": ts, "case_id": case_id}
                upsert_networkx_edge(case_id, src, tgt, relation=rel, weight=1.0, timestamp=ts, properties=props)
                edges_added.append({"source": src, "target": tgt, "relation": rel, "properties": props})

            elif r_type in ("file_artifact", "file"):
                src = str(art.get("owner_id") or art.get("sender") or "UNKNOWN")
                tgt = str(art.get("transferred_to_id") or art.get("receiver") or "UNKNOWN")
                fname = str(art.get("filename") or "file.bin")
                fhash = str(art.get("hash_sha256") or art.get("file_hash") or "")
                rel = "TRANSFERRED_FILE"
                props = {"record_id": r_id, "filename": fname, "hash_sha256": fhash, "timestamp": ts, "case_id": case_id}
                if tgt and tgt != "UNKNOWN":
                    upsert_networkx_edge(case_id, src, tgt, relation=rel, weight=1.0, timestamp=ts, properties=props)
                    edges_added.append({"source": src, "target": tgt, "relation": rel, "properties": props})

            elif r_type in ("location_ping", "co_located", "location"):
                if r_type == "co_located" or "distance_km" in art:
                    src = str(art.get("entity1") or art.get("source") or "UNKNOWN")
                    tgt = str(art.get("entity2") or art.get("target") or "UNKNOWN")
                    dist = float(art.get("distance_km", 0.0))
                    rel = "CO_LOCATED"
                    props = {"distance_km": dist, "timestamp": ts, "case_id": case_id}
                    upsert_networkx_edge(case_id, src, tgt, relation=rel, weight=1.0, timestamp=ts, properties=props)
                    edges_added.append({"source": src, "target": tgt, "relation": rel, "properties": props})

            elif r_type == "browser_history":
                src = str(art.get("entity_id") or "UNKNOWN")
                url = str(art.get("url") or "")
                props = {"record_id": r_id, "url": url, "timestamp": ts, "case_id": case_id}
                upsert_networkx_edge(case_id, src, case_id, relation="BROWSED", weight=0.5, timestamp=ts, properties=props)
                edges_added.append({"source": src, "target": case_id, "relation": "BROWSED", "properties": props})

        # 2. Persist to Neo4j if available
        driver = self.get_driver()
        if driver and is_neo4j_available():
            try:
                with driver.session() as session:
                    # MERGE Case node
                    session.run("""
                        MERGE (c:Case {case_id: $case_id})
                        SET c.note = $note,
                            c.loaded_at = $loaded_at
                    """, case_id=case_id, note=note, loaded_at=now_iso)

                    # MERGE Entity nodes and HAS_ENTITY edges
                    for ent in entities:
                        e_id = str(ent.get("entity_id") or ent.get("id") or ent.get("name") or "UNKNOWN")
                        name = str(ent.get("name") or e_id)
                        session.run("""
                            MERGE (c:Case {case_id: $case_id})
                            MERGE (e:Entity {entity_id: $entity_id, case_id: $case_id})
                            SET e.name = $name,
                                e.phone = $phone,
                                e.device_id = $device_id,
                                e.ip = $ip
                            MERGE (c)-[:HAS_ENTITY {case_id: $case_id}]->(e)
                        """, case_id=case_id, entity_id=e_id, name=name,
                             phone=str(ent.get("phone", "")),
                             device_id=str(ent.get("device_id", "")),
                             ip=str(ent.get("ip", "")))

                    # MERGE Relationships
                    for edge in edges_added:
                        src = edge["source"]
                        tgt = edge["target"]
                        rel = edge["relation"]
                        props = edge["properties"]

                        if rel == "CALLED":
                            session.run("""
                                MERGE (a:Entity {entity_id: $src, case_id: $case_id})
                                MERGE (b:Entity {entity_id: $tgt, case_id: $case_id})
                                CREATE (a)-[r:CALLED {
                                    record_id: $record_id,
                                    duration_sec: $duration_sec,
                                    timestamp: $timestamp,
                                    case_id: $case_id
                                }]->(b)
                            """, src=src, tgt=tgt, case_id=case_id,
                                 record_id=props.get("record_id", ""),
                                 duration_sec=props.get("duration_sec", 0),
                                 timestamp=props.get("timestamp", ""))

                        elif rel == "MESSAGED":
                            session.run("""
                                MERGE (a:Entity {entity_id: $src, case_id: $case_id})
                                MERGE (b:Entity {entity_id: $tgt, case_id: $case_id})
                                CREATE (a)-[r:MESSAGED {
                                    record_id: $record_id,
                                    platform: $platform,
                                    timestamp: $timestamp,
                                    case_id: $case_id
                                }]->(b)
                            """, src=src, tgt=tgt, case_id=case_id,
                                 record_id=props.get("record_id", ""),
                                 platform=props.get("platform", "Chat"),
                                 timestamp=props.get("timestamp", ""))

                        elif rel == "TRANSFERRED_FILE":
                            session.run("""
                                MERGE (a:Entity {entity_id: $src, case_id: $case_id})
                                MERGE (b:Entity {entity_id: $tgt, case_id: $case_id})
                                CREATE (a)-[r:TRANSFERRED_FILE {
                                    record_id: $record_id,
                                    filename: $filename,
                                    hash_sha256: $hash_sha256,
                                    timestamp: $timestamp,
                                    case_id: $case_id
                                }]->(b)
                            """, src=src, tgt=tgt, case_id=case_id,
                                 record_id=props.get("record_id", ""),
                                 filename=props.get("filename", ""),
                                 hash_sha256=props.get("hash_sha256", ""),
                                 timestamp=props.get("timestamp", ""))

                        elif rel == "CO_LOCATED":
                            session.run("""
                                MERGE (a:Entity {entity_id: $src, case_id: $case_id})
                                MERGE (b:Entity {entity_id: $tgt, case_id: $case_id})
                                CREATE (a)-[r:CO_LOCATED {
                                    distance_km: $distance_km,
                                    timestamp: $timestamp,
                                    case_id: $case_id
                                }]->(b)
                            """, src=src, tgt=tgt, case_id=case_id,
                                 distance_km=props.get("distance_km", 0.0),
                                 timestamp=props.get("timestamp", ""))
            except Exception as e:
                logger.error(f"Neo4j batch ingestion error for case {case_id}: {e}")

        return {
            "case_id": case_id,
            "entities_loaded": len(entities),
            "artifacts_loaded": len(artifacts),
            "edges_loaded": len(edges_added),
            "engine": "Neo4j 5.20 + NetworkX Dual Engine"
        }

    def to_graph_json(self, case_id: str) -> Dict[str, Any]:
        """
        Query and return frontend-ready graph JSON scoped to case_id.
        Queries Neo4j with Cypher when available; falls back smoothly to NetworkX.
        """
        driver = self.get_driver()
        if driver and is_neo4j_available():
            try:
                with driver.session() as session:
                    result = session.run("""
                        MATCH (n {case_id: $case_id})
                        OPTIONAL MATCH (n)-[r {case_id: $case_id}]->(m {case_id: $case_id})
                        RETURN
                            collect(DISTINCT {
                                id: COALESCE(n.entity_id, n.id, n.case_id, id(n)),
                                type: labels(n)[0],
                                label: COALESCE(n.name, n.case_id, n.entity_id, "Entity"),
                                properties: properties(n)
                            }) AS nodes,
                            collect(DISTINCT CASE
                                WHEN m IS NULL THEN NULL
                                ELSE {
                                    source: COALESCE(n.entity_id, n.id, n.case_id),
                                    target: COALESCE(m.entity_id, m.id, m.case_id),
                                    relation: type(r),
                                    type: type(r),
                                    timestamp: COALESCE(r.timestamp, ""),
                                    properties: properties(r)
                                }
                            END) AS links
                    """, case_id=case_id).single()

                    if result:
                        raw_nodes = result["nodes"] or []
                        raw_links = [l for l in (result["links"] or []) if l is not None]
                        node_map = {n["id"]: n for n in raw_nodes if n.get("id")}

                        for l in raw_links:
                            if l["source"] not in node_map:
                                node_map[l["source"]] = {"id": l["source"], "type": "Entity", "label": l["source"]}
                            if l["target"] not in node_map:
                                node_map[l["target"]] = {"id": l["target"], "type": "Entity", "label": l["target"]}

                        nodes_list = list(node_map.values())
                        return {
                            "case_id": case_id,
                            "nodes": nodes_list,
                            "links": raw_links,
                            "edges": raw_links,
                            "metadata": {
                                "node_count": len(nodes_list),
                                "link_count": len(raw_links),
                                "engine": "Neo4j Cypher",
                                "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
                            }
                        }
            except Exception as e:
                logger.warning(f"Neo4j query to_graph_json failed ({e}), using NetworkX fallback.")

        # NetworkX fallback
        fallback = export_networkx_graph_json(case_id)
        fallback["metadata"]["engine"] = "NetworkX Core"
        return fallback

    def shortest_path(self, case_id: str, source: str, target: str) -> Dict[str, Any]:
        """Compute shortest criminal network path between two entities in a case."""
        import networkx as nx
        G = get_networkx_graph(case_id)
        if G and source in G and target in G:
            try:
                path = nx.shortest_path(G, source=source, target=target)
                return {
                    "case_id": case_id,
                    "source": source,
                    "target": target,
                    "path_length": len(path) - 1,
                    "path": path,
                    "exists": True
                }
            except nx.NetworkXNoPath:
                return {"case_id": case_id, "source": source, "target": target, "path": [], "exists": False}
        return {"case_id": case_id, "source": source, "target": target, "path": [], "exists": False}

    def timeline(self, case_id: str, entity_id: Optional[str] = None, limit: int = 500) -> List[Dict[str, Any]]:
        """Retrieve chronological timeline of forensic events for a case."""
        graph_data = self.to_graph_json(case_id)
        links = graph_data.get("links", [])
        events = []
        for l in links:
            ts = l.get("timestamp") or l.get("properties", {}).get("timestamp", "")
            src = l.get("source")
            tgt = l.get("target")
            if entity_id and entity_id not in (src, tgt):
                continue
            if ts:
                events.append({
                    "timestamp": ts,
                    "relation": l.get("relation", "RELATED"),
                    "source": src,
                    "target": tgt,
                    "properties": l.get("properties", {})
                })
        events.sort(key=lambda x: str(x.get("timestamp", "")))
        return events[:limit]

    def delete_case(self, case_id: str) -> None:
        """Delete all case-scoped nodes and relationships from Neo4j and NetworkX."""
        reset_networkx_graph(case_id)
        driver = self.get_driver()
        if driver and is_neo4j_available():
            try:
                with driver.session() as session:
                    session.run("MATCH (n {case_id: $case_id}) DETACH DELETE n", case_id=case_id)
            except Exception as e:
                logger.warning(f"Error deleting case {case_id} from Neo4j: {e}")

# Global singleton instance
neo4j_engine = Neo4jGraphEngine()
