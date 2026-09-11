import logging
import networkx as nx
from typing import Dict, List, Any, Optional, Tuple
from app.graph.networkx_engine import get_networkx_graph

logger = logging.getLogger(__name__)

MANDATORY_ANALYTICS_DISCLAIMER = (
    "This score reflects network position and pattern frequency only. It is not a prediction of "
    "criminal behavior and must not be treated as a finding — all flagged individuals require "
    "independent human investigation."
)

def compute_pagerank(case_id: str) -> Dict[str, float]:
    """Compute PageRank scores for nodes in the case graph."""
    g = get_networkx_graph(case_id)
    if len(g) == 0:
        return {}
    try:
        return nx.pagerank(g, alpha=0.85, max_iter=200)
    except Exception as e:
        logger.warning(f"PageRank computation exception: {e}")
        # Return uniform if failed
        n = len(g)
        return {node: 1.0 / n for node in g.nodes()}

def compute_betweenness_centrality(case_id: str) -> Dict[str, float]:
    """Compute Betweenness Centrality (broker/bridge score)."""
    g = get_networkx_graph(case_id)
    if len(g) == 0:
        return {}
    try:
        return nx.betweenness_centrality(g, normalized=True)
    except Exception as e:
        logger.warning(f"Betweenness computation exception: {e}")
        return {node: 0.0 for node in g.nodes()}

def detect_bridge_nodes(case_id: str) -> Dict[str, Any]:
    """Detect cut-vertices / bridge nodes whose removal partitions the network."""
    g = get_networkx_graph(case_id)
    undirected_g = g.to_undirected()
    
    bridges = []
    cut_vertices = []
    
    if len(undirected_g) > 2:
        try:
            cut_vertices = list(nx.articulation_points(undirected_g))
            bridges = [list(e) for e in nx.bridges(undirected_g)]
        except Exception as e:
            logger.warning(f"Bridge detection exception: {e}")

    results = []
    for cv in cut_vertices:
        node_data = g.nodes.get(cv, {})
        results.append({
            "id": cv,
            "label": node_data.get("label", cv),
            "type": node_data.get("type", "Entity"),
            "role": "Cut-Vertex (Critical Connector)",
            "impact": "Removing this entity partitions the network into disconnected components"
        })

    return {
        "case_id": case_id,
        "cut_vertices": results,
        "bridge_edges": bridges,
        "disclaimer": MANDATORY_ANALYTICS_DISCLAIMER
    }

def detect_communities(case_id: str) -> Dict[str, Any]:
    """Detect modular communities / sub-cells using Louvain or greedy modularity."""
    g = get_networkx_graph(case_id)
    undirected_g = g.to_undirected()
    
    if len(undirected_g) < 2:
        return {
            "case_id": case_id,
            "communities": [],
            "total_communities": 0,
            "disclaimer": MANDATORY_ANALYTICS_DISCLAIMER
        }

    try:
        communities = nx.community.louvain_communities(undirected_g, seed=42)
    except Exception:
        try:
            communities = list(nx.community.greedy_modularity_communities(undirected_g))
        except Exception as e:
            logger.warning(f"Community detection exception: {e}")
            communities = [set(undirected_g.nodes())]

    formatted = []
    for idx, comm in enumerate(communities):
        members = []
        for m in comm:
            m_data = g.nodes.get(m, {})
            members.append({
                "id": m,
                "label": m_data.get("label", m),
                "type": m_data.get("type", "Entity")
            })
        formatted.append({
            "community_id": idx + 1,
            "member_count": len(members),
            "members": members
        })

    return {
        "case_id": case_id,
        "total_communities": len(formatted),
        "communities": formatted,
        "disclaimer": MANDATORY_ANALYTICS_DISCLAIMER
    }

def predict_adamic_adar_links(case_id: str, top_k: int = 10) -> Dict[str, Any]:
    """Predict hidden or unobserved links based on shared-neighbor topology."""
    g = get_networkx_graph(case_id)
    undirected_g = g.to_undirected()

    if len(undirected_g) < 3:
        return {
            "case_id": case_id,
            "predicted_links": [],
            "disclaimer": MANDATORY_ANALYTICS_DISCLAIMER
        }

    # Find non-edges
    non_edges = list(nx.non_edges(undirected_g))
    if not non_edges:
        return {
            "case_id": case_id,
            "predicted_links": [],
            "disclaimer": MANDATORY_ANALYTICS_DISCLAIMER
        }

    try:
        preds = nx.adamic_adar_index(undirected_g, non_edges)
        scored = []
        for u, v, p in preds:
            if p > 0:
                scored.append({
                    "source": u,
                    "target": v,
                    "score": round(float(p), 4),
                    "reason": "High shared neighborhood topology"
                })
        scored.sort(key=lambda x: x["score"], reverse=True)
        results = scored[:top_k]
    except Exception as e:
        logger.warning(f"Adamic-Adar prediction exception: {e}")
        results = []

    return {
        "case_id": case_id,
        "predicted_links": results,
        "disclaimer": MANDATORY_ANALYTICS_DISCLAIMER
    }

def compute_investigative_priority_scores(
    case_id: str,
    suspicious_call_counts: Optional[Dict[str, int]] = None,
    document_mention_counts: Optional[Dict[str, int]] = None,
    fuzzy_match_counts: Optional[Dict[str, int]] = None,
    financial_flag_counts: Optional[Dict[str, int]] = None,
    limit: int = 10
) -> Dict[str, Any]:
    """
    Compute 7-Dimensional Explainable Investigative Priority Score (0–100):
    1. Network Connectivity / Degree (20%)
    2. PageRank Structural Centrality (15%)
    3. Bridge / Broker Role (15%)
    4. Suspicious Call Bursts (15%)
    5. Document Mentions (15%)
    6. Fuzzy / Alias Matches (10%)
    7. Financial Pattern Flags (10%)
    """
    g = get_networkx_graph(case_id)
    if len(g) == 0:
        return {
            "case_id": case_id,
            "top_influencers": [],
            "disclaimer": MANDATORY_ANALYTICS_DISCLAIMER
        }

    pageranks = compute_pagerank(case_id)
    betweenness = compute_betweenness_centrality(case_id)
    
    # Normalization baselines
    max_degree = max([deg for _, deg in g.degree()] or [1]) or 1
    max_pr = max(pageranks.values() or [1.0]) or 1.0
    max_bw = max(betweenness.values() or [1.0]) or 1.0

    call_flags = suspicious_call_counts or {}
    doc_mentions = document_mention_counts or {}
    fuzzy_matches = fuzzy_match_counts or {}
    fin_flags = financial_flag_counts or {}

    max_calls = max(call_flags.values() or [1]) or 1
    max_docs = max(doc_mentions.values() or [1]) or 1
    max_fuzzy = max(fuzzy_matches.values() or [1]) or 1
    max_fin = max(fin_flags.values() or [1]) or 1

    scores = []

    for node in g.nodes():
        node_data = g.nodes[node]
        deg = g.degree(node)
        pr = pageranks.get(node, 0.0)
        bw = betweenness.get(node, 0.0)
        
        c_flag = call_flags.get(node, 0)
        d_mention = doc_mentions.get(node, 1) # baseline 1 mention
        f_match = fuzzy_matches.get(node, 0)
        fn_flag = fin_flags.get(node, 0)

        # 7-dimension weighted calculation
        dim_connectivity = (deg / max_degree) * 20.0
        dim_pagerank = (pr / max_pr) * 15.0
        dim_betweenness = (bw / max_bw) * 15.0
        dim_calls = min(c_flag / max_calls, 1.0) * 15.0
        dim_mentions = min(d_mention / max_docs, 1.0) * 15.0
        dim_fuzzy = min(f_match / max_fuzzy, 1.0) * 10.0
        dim_financial = min(fn_flag / max_fin, 1.0) * 10.0

        total_score = min(
            dim_connectivity + dim_pagerank + dim_betweenness +
            dim_calls + dim_mentions + dim_fuzzy + dim_financial,
            100.0
        )

        scores.append({
            "id": node,
            "label": node_data.get("label", node),
            "type": node_data.get("type", "Entity"),
            "priority_score": round(total_score, 1),
            "pagerank": round(pr, 4),
            "betweenness": round(bw, 4),
            "degree": deg,
            "score_breakdown": {
                "connectivity_weight_20": round(dim_connectivity, 1),
                "pagerank_weight_15": round(dim_pagerank, 1),
                "bridge_weight_15": round(dim_betweenness, 1),
                "suspicious_calls_weight_15": round(dim_calls, 1),
                "document_mentions_weight_15": round(dim_mentions, 1),
                "fuzzy_match_weight_10": round(dim_fuzzy, 1),
                "financial_flags_weight_10": round(dim_financial, 1)
            }
        })

    scores.sort(key=lambda x: x["priority_score"], reverse=True)

    return {
        "case_id": case_id,
        "top_influencers": scores[:limit],
        "total_ranked_entities": len(scores),
        "disclaimer": MANDATORY_ANALYTICS_DISCLAIMER
    }
