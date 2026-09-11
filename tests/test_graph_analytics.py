import pytest
from app.graph.build_graph import write_graph, get_case_graph
from app.graph.analytics import (
    compute_pagerank,
    compute_betweenness_centrality,
    detect_bridge_nodes,
    detect_communities,
    predict_adamic_adar_links,
    compute_investigative_priority_scores,
    MANDATORY_ANALYTICS_DISCLAIMER
)

def test_graph_construction_and_retrieval():
    case_id = "CASE-GRAPH-001"
    records = [
        {
            "source": "Suspect_A", "target": "Suspect_B",
            "source_type": "Person", "target_type": "Person",
            "relation": "CALLED", "weight": 2.0, "timestamp": "2026-01-01"
        },
        {
            "source": "Suspect_B", "target": "Suspect_C",
            "source_type": "Person", "target_type": "Person",
            "relation": "TRANSACTED_WITH", "weight": 5.0, "timestamp": "2026-01-02"
        },
        {
            "source": "Suspect_A", "target": "Shakti_Traders",
            "source_type": "Person", "target_type": "Organization",
            "relation": "AFFILIATED_WITH", "weight": 1.0
        }
    ]

    delta = write_graph(cid=case_id, records=records, is_rebuild=True)
    assert len(delta["nodes_added"]) >= 4

    graph_data = get_case_graph(cid=case_id)
    assert len(graph_data["nodes"]) >= 4
    assert len(graph_data["links"]) == 3

def test_network_algorithms():
    case_id = "CASE-GRAPH-001"
    
    # 1. PageRank
    pr = compute_pagerank(case_id)
    assert len(pr) >= 4
    assert all(val > 0 for val in pr.values())

    # 2. Betweenness
    bw = compute_betweenness_centrality(case_id)
    assert "Suspect_B" in bw # Central node
    assert bw["Suspect_B"] > 0

    # 3. Bridge Nodes
    bridges = detect_bridge_nodes(case_id)
    assert bridges["disclaimer"] == MANDATORY_ANALYTICS_DISCLAIMER
    assert len(bridges["cut_vertices"]) >= 1

    # 4. Communities
    comm = detect_communities(case_id)
    assert comm["total_communities"] >= 1
    assert comm["disclaimer"] == MANDATORY_ANALYTICS_DISCLAIMER

    # 5. Priority Scores
    priority = compute_investigative_priority_scores(case_id=case_id, limit=5)
    assert len(priority["top_influencers"]) >= 1
    top = priority["top_influencers"][0]
    assert 0 <= top["priority_score"] <= 100
    assert "connectivity_weight_20" in top["score_breakdown"]
    assert "financial_flags_weight_10" in top["score_breakdown"]
    assert priority["disclaimer"] == MANDATORY_ANALYTICS_DISCLAIMER
