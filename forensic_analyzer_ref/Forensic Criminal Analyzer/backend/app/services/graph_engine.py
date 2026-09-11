"""
Graph Engine
------------
Builds an entity-relationship graph from ingested forensic artifacts and
runs investigative analysis on it:

  - Centrality analysis      -> who is the "hub" of the network
  - Community detection      -> cluster entities into likely groups
  - Anomaly scoring          -> flag entities/edges with unusual patterns
  - Link prediction          -> suggest probable-but-unconfirmed connections
  - Shortest path            -> "how is A connected to B"

This is an INVESTIGATIVE AID: it surfaces relationships and anomaly scores
for a human analyst to review. It does not make accusations or automated
determinations about guilt or involvement.
"""
import networkx as nx
from collections import defaultdict
from sklearn.ensemble import IsolationForest
from datetime import datetime
from math import radians, sin, cos, sqrt, atan2
import numpy as np


def _haversine_km(lat1, lng1, lat2, lng2):
    R = 6371.0
    dlat = radians(lat2 - lat1)
    dlng = radians(lng2 - lng1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlng / 2) ** 2
    return R * 2 * atan2(sqrt(a), sqrt(1 - a))


def _parse_ts(ts):
    try:
        return datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        return None


class ForensicGraphEngine:
    def __init__(self, case_data: dict):
        self.case_id = case_data.get("case_id", "UNKNOWN")
        self.entities = {e["entity_id"]: e for e in case_data.get("entities", [])}
        self.artifacts = case_data.get("artifacts", [])
        self.graph = nx.MultiGraph()
        self._build_graph()
        self._add_colocation_edges()

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------
    def _build_graph(self):
        for eid, e in self.entities.items():
            self.graph.add_node(eid, **e, node_type="entity")

        for art in self.artifacts:
            rtype = art.get("record_type")

            if rtype == "call":
                self._add_edge(art["caller_id"], art["callee_id"], "call", art)
            elif rtype == "chat":
                self._add_edge(art["sender_id"], art["receiver_id"], "chat", art)
            elif rtype == "browser_history":
                # single-entity artifact; attach as node attribute count only
                continue
            elif rtype == "location_ping":
                # handled separately in _add_colocation_edges
                continue
            elif rtype == "file_artifact":
                if "transferred_to_id" in art:
                    self._add_edge(art["owner_id"], art["transferred_to_id"], "file_transfer", art)

    def _add_colocation_edges(self, max_distance_km=1.5, max_minutes=90):
        """Forensic co-location analysis: if two different entities have
        location pings within max_distance_km and max_minutes of each other,
        that's evidence they were physically near each other — a real
        technique used in cell-site/geolocation forensic analysis."""
        pings = [a for a in self.artifacts if a.get("record_type") == "location_ping"]
        for p in pings:
            p["_ts_parsed"] = _parse_ts(p.get("timestamp"))
        pings = [p for p in pings if p["_ts_parsed"] is not None]
        pings.sort(key=lambda p: p["_ts_parsed"])

        seen_pairs = set()
        n = len(pings)
        for i in range(n):
            pi = pings[i]
            for j in range(i + 1, n):
                pj = pings[j]
                dt = abs((pj["_ts_parsed"] - pi["_ts_parsed"]).total_seconds()) / 60.0
                if dt > max_minutes:
                    break  # sorted by time — no further j will be within window
                if pi["entity_id"] == pj["entity_id"]:
                    continue
                dist = _haversine_km(pi["lat"], pi["lng"], pj["lat"], pj["lng"])
                if dist <= max_distance_km:
                    a, b = pi["entity_id"], pj["entity_id"]
                    pair_key = (min(a, b), max(a, b), pi["record_id"], pj["record_id"])
                    if pair_key in seen_pairs:
                        continue
                    seen_pairs.add(pair_key)
                    self._add_edge(a, b, "colocation", {
                        "record_id": f"coloc-{pi['record_id']}-{pj['record_id']}",
                        "timestamp": pi["timestamp"],
                    })


    def _add_edge(self, a, b, kind, artifact):
        if a not in self.graph or b not in self.graph or a == b:
            return
        self.graph.add_edge(a, b, key=artifact["record_id"], kind=kind,
                             timestamp=artifact.get("timestamp"))

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------
    def centrality_analysis(self):
        """Returns degree, betweenness, and eigenvector centrality per entity.
        High betweenness = likely intermediary/broker. High degree = hub."""
        simple = nx.Graph(self.graph)  # collapse multi-edges for centrality calc
        degree = nx.degree_centrality(simple)
        betweenness = nx.betweenness_centrality(simple)
        try:
            eigen = nx.eigenvector_centrality(simple, max_iter=500)
        except (nx.PowerIterationFailedConvergence, nx.AmbiguousSolution):
            eigen = {n: 0.0 for n in simple.nodes}

        results = []
        for n in simple.nodes:
            results.append({
                "entity_id": n,
                "name": self.entities.get(n, {}).get("name", n),
                "degree_centrality": round(degree.get(n, 0), 4),
                "betweenness_centrality": round(betweenness.get(n, 0), 4),
                "eigenvector_centrality": round(eigen.get(n, 0), 4),
            })
        results.sort(key=lambda r: r["betweenness_centrality"], reverse=True)
        return results

    def community_detection(self):
        """Clusters entities into likely groups using greedy modularity."""
        simple = nx.Graph(self.graph)
        if simple.number_of_edges() == 0:
            return []
        communities = nx.algorithms.community.greedy_modularity_communities(simple)
        result = []
        for i, comm in enumerate(communities):
            result.append({
                "community_id": i,
                "size": len(comm),
                "members": [
                    {"entity_id": n, "name": self.entities.get(n, {}).get("name", n)}
                    for n in comm
                ],
            })
        return result

    def anomaly_scores(self):
        """Flags entities with unusual activity patterns using Isolation Forest
        over simple behavioral features (degree, call volume, off-hour activity).
        Score closer to 1 = more anomalous. This is a triage signal, not a verdict."""
        simple = nx.Graph(self.graph)
        features = []
        node_ids = list(simple.nodes)

        # Feature: degree, edge count (raw multigraph), distinct edge kinds, off-hour ratio
        for n in node_ids:
            degree = simple.degree(n)
            edges = list(self.graph.edges(n, data=True, keys=True))
            edge_count = len(edges)
            kinds = set(d.get("kind") for _, _, k, d in edges)
            off_hour = 0
            total_ts = 0
            for _, _, k, d in edges:
                ts = d.get("timestamp")
                if ts:
                    total_ts += 1
                    hour = int(ts[11:13]) if len(ts) > 13 else 12
                    if hour < 6 or hour > 22:
                        off_hour += 1
            off_hour_ratio = (off_hour / total_ts) if total_ts else 0
            features.append([degree, edge_count, len(kinds), off_hour_ratio])

        if len(features) < 3:
            return []

        X = np.array(features)
        clf = IsolationForest(contamination=0.2, random_state=42)
        clf.fit(X)
        raw_scores = clf.decision_function(X)  # higher = more normal
        # normalize to 0..1 where 1 = most anomalous
        norm = (raw_scores.max() - raw_scores) / (raw_scores.max() - raw_scores.min() + 1e-9)

        results = []
        for i, n in enumerate(node_ids):
            results.append({
                "entity_id": n,
                "name": self.entities.get(n, {}).get("name", n),
                "anomaly_score": round(float(norm[i]), 4),
                "degree": features[i][0],
                "edge_count": features[i][1],
                "distinct_artifact_kinds": features[i][2],
                "off_hour_activity_ratio": round(features[i][3], 3),
            })
        results.sort(key=lambda r: r["anomaly_score"], reverse=True)
        return results

    def link_prediction(self, top_n=15):
        """Suggests probable-but-unconfirmed connections using Adamic-Adar
        index over the existing graph (common in link-prediction literature)."""
        simple = nx.Graph(self.graph)
        non_edges = list(nx.non_edges(simple))
        if not non_edges:
            return []
        preds = list(nx.adamic_adar_index(simple, non_edges))
        preds.sort(key=lambda x: x[2], reverse=True)
        results = []
        for a, b, score in preds[:top_n]:
            if score <= 0:
                continue
            results.append({
                "entity_a": a,
                "entity_a_name": self.entities.get(a, {}).get("name", a),
                "entity_b": b,
                "entity_b_name": self.entities.get(b, {}).get("name", b),
                "predicted_score": round(score, 4),
            })
        return results

    def shortest_path(self, source, target):
        simple = nx.Graph(self.graph)
        if source not in simple or target not in simple:
            return {"error": "Unknown entity id(s)"}
        try:
            path = nx.shortest_path(simple, source, target)
            return {
                "path": path,
                "path_names": [self.entities.get(n, {}).get("name", n) for n in path],
                "length": len(path) - 1,
            }
        except nx.NetworkXNoPath:
            return {"error": "No path found between these entities"}

    def timeline(self, entity_id=None, limit=500):
        """Chronological event timeline across all artifact types, optionally
        filtered to one entity. Standard forensic-analysis view — investigators
        typically work a timeline alongside the network graph."""
        events = []
        for art in self.artifacts:
            rtype = art.get("record_type")
            ts = art.get("timestamp")
            if not ts:
                continue

            if rtype == "call":
                if entity_id and entity_id not in (art["caller_id"], art["callee_id"]):
                    continue
                events.append({
                    "timestamp": ts, "type": "call",
                    "summary": f"{self._name(art['caller_id'])} called {self._name(art['callee_id'])} "
                               f"({art.get('duration_sec', 0)}s)",
                    "entities": [art["caller_id"], art["callee_id"]],
                })
            elif rtype == "chat":
                if entity_id and entity_id not in (art["sender_id"], art["receiver_id"]):
                    continue
                events.append({
                    "timestamp": ts, "type": "chat",
                    "summary": f"{self._name(art['sender_id'])} messaged {self._name(art['receiver_id'])} "
                               f"via {art.get('platform', 'unknown platform')}",
                    "entities": [art["sender_id"], art["receiver_id"]],
                })
            elif rtype == "browser_history":
                if entity_id and entity_id != art["entity_id"]:
                    continue
                events.append({
                    "timestamp": ts, "type": "browser_history",
                    "summary": f"{self._name(art['entity_id'])} visited {art.get('url', '')}",
                    "entities": [art["entity_id"]],
                })
            elif rtype == "file_artifact":
                involved = [art["owner_id"]] + ([art["transferred_to_id"]] if "transferred_to_id" in art else [])
                if entity_id and entity_id not in involved:
                    continue
                if "transferred_to_id" in art:
                    summary = (f"{self._name(art['owner_id'])} transferred {art.get('filename')} "
                               f"to {self._name(art['transferred_to_id'])}")
                else:
                    summary = f"{self._name(art['owner_id'])} accessed file {art.get('filename')}"
                events.append({"timestamp": ts, "type": "file_artifact", "summary": summary, "entities": involved})
            elif rtype == "location_ping":
                if entity_id and entity_id != art["entity_id"]:
                    continue
                events.append({
                    "timestamp": ts, "type": "location_ping",
                    "summary": f"{self._name(art['entity_id'])} pinged near ({art.get('lat')}, {art.get('lng')})",
                    "entities": [art["entity_id"]],
                })

        events.sort(key=lambda e: e["timestamp"], reverse=True)
        return events[:limit]

    def _name(self, entity_id):
        return self.entities.get(entity_id, {}).get("name", entity_id)

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------
    def to_graph_json(self):
        """Node/edge JSON shaped for the frontend graph visualization."""
        simple_edges = defaultdict(lambda: defaultdict(int))
        for u, v, k, d in self.graph.edges(data=True, keys=True):
            simple_edges[(u, v)][d.get("kind", "unknown")] += 1

        nodes = [
            {
                "id": n,
                "name": self.entities.get(n, {}).get("name", n),
                "phone": self.entities.get(n, {}).get("phone"),
                "device_id": self.entities.get(n, {}).get("device_id"),
            }
            for n in self.graph.nodes
        ]
        edges = []
        for (u, v), kinds in simple_edges.items():
            edges.append({
                "source": u,
                "target": v,
                "weight": sum(kinds.values()),
                "kinds": kinds,
            })
        return {"nodes": nodes, "edges": edges}
