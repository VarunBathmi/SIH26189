import pytest
from app.graph.neo4j_engine import neo4j_engine

def test_neo4j_engine_case_lifecycle():
    case_id = "CASE-NEO-001"

    case_data = {
        "case_id": case_id,
        "note": "Operation Night Hawk",
        "entities": [
            {"entity_id": "N-01", "name": "Rohan Sharma", "phone": "9876543210"},
            {"entity_id": "N-02", "name": "Vikas Yadav", "phone": "9811002233"},
            {"entity_id": "N-03", "name": "Suresh Raina", "phone": "9822334455"}
        ],
        "artifacts": [
            {"record_type": "call", "record_id": "CALL-01", "caller_id": "N-01", "callee_id": "N-02", "duration_sec": 300, "timestamp": "2026-02-01T10:00:00"},
            {"record_type": "chat", "record_id": "CHAT-01", "sender_id": "N-02", "receiver_id": "N-03", "platform": "Telegram", "timestamp": "2026-02-01T11:00:00"},
            {"record_type": "file_artifact", "record_id": "FILE-01", "owner_id": "N-01", "transferred_to_id": "N-03", "filename": "ledger.xlsx", "hash_sha256": "abc123hash", "timestamp": "2026-02-01T12:00:00"},
            {"record_type": "co_located", "record_id": "COLOC-01", "entity1": "N-01", "entity2": "N-02", "distance_km": 0.12, "timestamp": "2026-02-01T10:00:00"}
        ]
    }

    # 1. Load case
    load_res = neo4j_engine.load_case(case_data)
    assert load_res["case_id"] == case_id
    assert load_res["entities_loaded"] == 3
    assert load_res["artifacts_loaded"] == 4

    # 2. Graph JSON verification
    graph_json = neo4j_engine.to_graph_json(case_id)
    assert graph_json["case_id"] == case_id
    assert len(graph_json["nodes"]) >= 3
    assert len(graph_json["links"]) >= 4

    # 3. Shortest path
    path_res = neo4j_engine.shortest_path(case_id, source="N-01", target="N-03")
    assert path_res["exists"] is True
    assert path_res["path_length"] >= 1
    assert "N-01" in path_res["path"]
    assert "N-03" in path_res["path"]

    # 4. Timeline
    timeline_events = neo4j_engine.timeline(case_id)
    assert len(timeline_events) >= 4
    assert all("timestamp" in ev for ev in timeline_events)

    # 5. Delete case
    neo4j_engine.delete_case(case_id)
    deleted_graph = neo4j_engine.to_graph_json(case_id)
    assert len(deleted_graph["nodes"]) == 0

def test_neo4j_engine_strict_case_isolation():
    """
    Test that Case 1 and Case 2 with overlapping entity IDs (e.g. 'SUSPECT-X')
    remain strictly isolated with zero cross-case edge leakage.
    """
    case_1 = "CASE-ISOLATION-001"
    case_2 = "CASE-ISOLATION-002"

    data_1 = {
        "case_id": case_1,
        "entities": [{"entity_id": "SHARED-E1", "name": "Agent Smith"}],
        "artifacts": [{"record_type": "call", "caller_id": "SHARED-E1", "callee_id": "CASE1-TARGET", "timestamp": "2026-01-01"}]
    }

    data_2 = {
        "case_id": case_2,
        "entities": [{"entity_id": "SHARED-E1", "name": "Agent Smith"}],
        "artifacts": [{"record_type": "chat", "sender_id": "SHARED-E1", "receiver_id": "CASE2-TARGET", "timestamp": "2026-02-02"}]
    }

    neo4j_engine.load_case(data_1)
    neo4j_engine.load_case(data_2)

    g1 = neo4j_engine.to_graph_json(case_1)
    g2 = neo4j_engine.to_graph_json(case_2)

    # Case 1 should have CASE1-TARGET and NOT CASE2-TARGET
    c1_node_ids = [n["id"] for n in g1["nodes"]]
    c2_node_ids = [n["id"] for n in g2["nodes"]]

    assert "CASE1-TARGET" in c1_node_ids
    assert "CASE2-TARGET" not in c1_node_ids

    assert "CASE2-TARGET" in c2_node_ids
    assert "CASE1-TARGET" not in c2_node_ids

    # Cleanup
    neo4j_engine.delete_case(case_1)
    neo4j_engine.delete_case(case_2)
