import logging
import networkx as nx
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)

# In-memory case graphs storage
_case_graphs: Dict[str, nx.DiGraph] = {}

def get_networkx_graph(case_id: str) -> nx.DiGraph:
    """Retrieve or initialize NetworkX DiGraph for a specific case."""
    if case_id not in _case_graphs:
        _case_graphs[case_id] = nx.DiGraph(case_id=case_id)
    return _case_graphs[case_id]

def reset_networkx_graph(case_id: str):
    """Reset the NetworkX graph for a specific case."""
    if case_id in _case_graphs:
        _case_graphs[case_id].clear()
    else:
        _case_graphs[case_id] = nx.DiGraph(case_id=case_id)

def upsert_networkx_node(
    case_id: str,
    node_id: str,
    node_type: str = "Entity",
    label: Optional[str] = None,
    properties: Optional[Dict[str, Any]] = None
):
    """Upsert node into the case's NetworkX graph."""
    g = get_networkx_graph(case_id)
    props = properties.copy() if properties else {}
    props["type"] = node_type
    props["label"] = label or node_id
    props["case_id"] = case_id

    if g.has_node(node_id):
        g.nodes[node_id].update(props)
    else:
        g.add_node(node_id, **props)

def upsert_networkx_edge(
    case_id: str,
    source: str,
    target: str,
    relation: str = "RELATED",
    weight: float = 1.0,
    timestamp: str = "",
    artifact_hash: str = "",
    properties: Optional[Dict[str, Any]] = None
):
    """Upsert directed edge into the case's NetworkX graph."""
    g = get_networkx_graph(case_id)
    props = properties.copy() if properties else {}
    props["relation"] = relation
    props["type"] = relation
    props["weight"] = float(weight)
    props["timestamp"] = str(timestamp)
    props["artifact_hash"] = str(artifact_hash)
    props["case_id"] = case_id

    # Ensure source and target nodes exist
    if not g.has_node(source):
        g.add_node(source, id=source, type="Entity", label=source, case_id=case_id)
    if not g.has_node(target):
        g.add_node(target, id=target, type="Entity", label=target, case_id=case_id)

    g.add_edge(source, target, **props)

def export_networkx_graph_json(case_id: str) -> Dict[str, Any]:
    """Export case graph in standardized frontend-ready JSON format."""
    g = get_networkx_graph(case_id)
    nodes = []
    for n, data in g.nodes(data=True):
        nodes.append({
            "id": n,
            "type": data.get("type", "Entity"),
            "label": data.get("label", n),
            "properties": {k: v for k, v in data.items() if k not in ("type", "label")}
        })

    links = []
    for u, v, data in g.edges(data=True):
        links.append({
            "source": u,
            "target": v,
            "relation": data.get("relation", "RELATED"),
            "type": data.get("relation", "RELATED"),
            "weight": data.get("weight", 1.0),
            "timestamp": data.get("timestamp", ""),
            "hash": data.get("artifact_hash", ""),
            "properties": {k: v for k, v in data.items() if k not in ("relation", "type", "weight", "timestamp", "artifact_hash")}
        })

    return {
        "case_id": case_id,
        "nodes": nodes,
        "links": links,
        "edges": links, # Dual compatibility for links and edges
        "metadata": {
            "node_count": len(nodes),
            "link_count": len(links),
            "is_directed": True
        }
    }
