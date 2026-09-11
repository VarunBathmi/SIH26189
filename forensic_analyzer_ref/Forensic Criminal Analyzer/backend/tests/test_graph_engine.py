import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.graph_engine import ForensicGraphEngine, _haversine_km


def test_graph_builds_expected_nodes_and_edges(small_case):
    engine = ForensicGraphEngine(small_case)
    assert set(engine.graph.nodes) == {"A", "B", "C", "D"}
    # A-B (call), B-C (call), A-C (chat), A-B (file_transfer) = 4 edges in the multigraph
    assert engine.graph.number_of_edges() == 4


def test_isolated_entity_has_no_edges(small_case):
    engine = ForensicGraphEngine(small_case)
    assert engine.graph.degree("D") == 0


def test_centrality_analysis_includes_all_entities(small_case):
    engine = ForensicGraphEngine(small_case)
    result = engine.centrality_analysis()
    ids = {r["entity_id"] for r in result}
    assert ids == {"A", "B", "C", "D"}


def test_centrality_ranks_by_betweenness_descending(small_case):
    engine = ForensicGraphEngine(small_case)
    result = engine.centrality_analysis()
    scores = [r["betweenness_centrality"] for r in result]
    assert scores == sorted(scores, reverse=True)


def test_shortest_path_finds_known_route(small_case):
    engine = ForensicGraphEngine(small_case)
    result = engine.shortest_path("A", "C")
    assert "error" not in result
    assert result["path"][0] == "A"
    assert result["path"][-1] == "C"
    assert result["length"] >= 1


def test_shortest_path_no_route_to_isolated_node(small_case):
    engine = ForensicGraphEngine(small_case)
    result = engine.shortest_path("A", "D")
    assert "error" in result


def test_shortest_path_unknown_entity(small_case):
    engine = ForensicGraphEngine(small_case)
    result = engine.shortest_path("A", "ZZZ")
    assert "error" in result


def test_to_graph_json_shape(small_case):
    engine = ForensicGraphEngine(small_case)
    gj = engine.to_graph_json()
    assert len(gj["nodes"]) == 4
    assert all("id" in n and "name" in n for n in gj["nodes"])
    assert all("source" in e and "target" in e and "weight" in e for e in gj["edges"])


def test_timeline_returns_events_sorted_descending(small_case):
    engine = ForensicGraphEngine(small_case)
    events = engine.timeline()
    timestamps = [e["timestamp"] for e in events]
    assert timestamps == sorted(timestamps, reverse=True)
    assert len(events) == 5  # all 5 artifacts produce a timeline event


def test_timeline_filters_by_entity(small_case):
    engine = ForensicGraphEngine(small_case)
    events = engine.timeline(entity_id="D")
    assert len(events) == 1
    assert events[0]["type"] == "browser_history"


def test_anomaly_scores_cover_all_entities(small_case):
    engine = ForensicGraphEngine(small_case)
    result = engine.anomaly_scores()
    ids = {r["entity_id"] for r in result}
    assert ids == {"A", "B", "C", "D"}
    for r in result:
        assert 0.0 <= r["anomaly_score"] <= 1.0


def test_link_prediction_does_not_include_existing_edges(small_case):
    engine = ForensicGraphEngine(small_case)
    predictions = engine.link_prediction()
    existing = {tuple(sorted((u, v))) for u, v in engine.graph.edges(data=False, keys=False)}
    for p in predictions:
        pair = tuple(sorted((p["entity_a"], p["entity_b"])))
        assert pair not in existing


def test_community_detection_covers_connected_entities(small_case):
    engine = ForensicGraphEngine(small_case)
    communities = engine.community_detection()
    covered = {m["entity_id"] for c in communities for m in c["members"]}
    # D is isolated and excluded from the simple graph community detection input
    assert covered.issubset({"A", "B", "C", "D"})
    assert "A" in covered and "B" in covered and "C" in covered


def test_haversine_zero_distance_for_same_point():
    assert _haversine_km(12.9, 77.6, 12.9, 77.6) == 0.0


def test_haversine_known_distance_approx():
    # Roughly 1 degree of latitude ≈ 111 km
    d = _haversine_km(0.0, 0.0, 1.0, 0.0)
    assert 108 < d < 113


def test_colocation_edges_created_for_close_pings():
    case = {
        "case_id": "COLOC-TEST",
        "entities": [
            {"entity_id": "A", "name": "Alice"},
            {"entity_id": "B", "name": "Bob"},
        ],
        "artifacts": [
            {"record_type": "location_ping", "record_id": "p1", "entity_id": "A",
             "lat": 12.9000, "lng": 77.6000, "timestamp": "2026-01-01T10:00:00"},
            {"record_type": "location_ping", "record_id": "p2", "entity_id": "B",
             "lat": 12.9005, "lng": 77.6005, "timestamp": "2026-01-01T10:10:00"},
        ],
    }
    engine = ForensicGraphEngine(case)
    kinds = [d.get("kind") for _, _, d in engine.graph.edges(data=True)]
    assert "colocation" in kinds


def test_colocation_not_created_for_far_pings():
    case = {
        "case_id": "COLOC-TEST-2",
        "entities": [
            {"entity_id": "A", "name": "Alice"},
            {"entity_id": "B", "name": "Bob"},
        ],
        "artifacts": [
            {"record_type": "location_ping", "record_id": "p1", "entity_id": "A",
             "lat": 12.90, "lng": 77.60, "timestamp": "2026-01-01T10:00:00"},
            {"record_type": "location_ping", "record_id": "p2", "entity_id": "B",
             "lat": 13.50, "lng": 78.20, "timestamp": "2026-01-01T10:10:00"},
        ],
    }
    engine = ForensicGraphEngine(case)
    assert engine.graph.number_of_edges() == 0
