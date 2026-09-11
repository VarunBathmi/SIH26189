import networkx as nx
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.security.auth import get_current_user
from app.graph.build_graph import get_case_graph
from app.graph.networkx_engine import get_networkx_graph
from app.graph.analytics import (
    compute_investigative_priority_scores,
    detect_communities as detect_communities_algo,
    detect_bridge_nodes as detect_bridge_nodes_algo,
    predict_adamic_adar_links,
    MANDATORY_ANALYTICS_DISCLAIMER
)

router = APIRouter(prefix="/graph", tags=["Graph Database & Network Analytics"])

@router.get("/overview", summary="Retrieve full case graph formatted for Cytoscape/Vis.js visualization")
def get_graph_overview(
    case_id: str = Query(..., description="Investigation Case ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return get_case_graph(cid=case_id)

@router.get("/person/{hash_id}", summary="Retrieve ego-network centered around a specific pseudonymized entity")
def get_ego_network(
    hash_id: str,
    case_id: Optional[str] = Query(None),
    depth: int = Query(1, ge=1, le=3),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Search across case graphs
    cid = case_id or "CASE001"
    g = get_networkx_graph(cid)
    
    if not g.has_node(hash_id):
        # Try finding node by label if hash_id is a name
        matching = [n for n in g.nodes() if g.nodes[n].get("label") == hash_id or n == hash_id]
        if matching:
            hash_id = matching[0]
        else:
            return {"case_id": cid, "center_node": hash_id, "nodes": [], "links": [], "message": "Node not found in graph"}

    ego_g = nx.ego_graph(g, hash_id, radius=depth, undirected=True)

    nodes = []
    for n, d in ego_g.nodes(data=True):
        nodes.append({"id": n, "type": d.get("type", "Entity"), "label": d.get("label", n)})

    links = []
    for u, v, d in ego_g.edges(data=True):
        links.append({
            "source": u,
            "target": v,
            "relation": d.get("relation", "RELATED"),
            "weight": d.get("weight", 1.0)
        })

    return {
        "case_id": cid,
        "center_node": hash_id,
        "depth": depth,
        "nodes": nodes,
        "links": links
    }

@router.get("/shortest-path", summary="Compute shortest relationship path between two entities")
def get_shortest_path(
    source: str = Query(..., description="Source node ID/hash"),
    target: str = Query(..., description="Target node ID/hash"),
    case_id: str = Query(..., description="Case ID"),
    current_user: dict = Depends(get_current_user)
):
    g = get_networkx_graph(case_id).to_undirected()

    if not g.has_node(source) or not g.has_node(target):
        raise HTTPException(status_code=404, detail="Source or target entity not found in case graph.")

    try:
        path = nx.shortest_path(g, source=source, target=target)
        edges = []
        for i in range(len(path) - 1):
            u, v = path[i], path[i+1]
            edge_data = g.get_edge_data(u, v) or {}
            edges.append({
                "source": u,
                "target": v,
                "relation": edge_data.get("relation", "LINKED")
            })
        return {
            "case_id": case_id,
            "source": source,
            "target": target,
            "path_length": len(path) - 1,
            "path_nodes": path,
            "path_edges": edges,
            "disclaimer": MANDATORY_ANALYTICS_DISCLAIMER
        }
    except nx.NetworkXNoPath:
        return {
            "case_id": case_id,
            "source": source,
            "target": target,
            "path_length": -1,
            "path_nodes": [],
            "message": "No connecting path found between specified entities."
        }

@router.get("/top-influencers", summary="Expose key structural influencers with 7-dimension Investigative Priority Score")
def get_top_influencers(
    case_id: str = Query(..., description="Case ID"),
    limit: int = Query(10, ge=1, le=50),
    current_user: dict = Depends(get_current_user)
):
    return compute_investigative_priority_scores(case_id=case_id, limit=limit)

@router.get("/communities", summary="Expose Louvain community detection and hidden sub-cell structures")
def get_communities(
    case_id: str = Query(..., description="Case ID"),
    current_user: dict = Depends(get_current_user)
):
    return detect_communities_algo(case_id=case_id)

@router.get("/bridge-nodes", summary="Expose cut-vertices and critical structural brokers")
def get_bridge_nodes(
    case_id: str = Query(..., description="Case ID"),
    current_user: dict = Depends(get_current_user)
):
    return detect_bridge_nodes_algo(case_id=case_id)

@router.get("/predicted-links", summary="Expose Adamic-Adar link prediction for unobserved associations")
def get_predicted_links(
    case_id: str = Query(..., description="Case ID"),
    limit: int = Query(10, ge=1, le=50),
    current_user: dict = Depends(get_current_user)
):
    return predict_adamic_adar_links(case_id=case_id, top_k=limit)
