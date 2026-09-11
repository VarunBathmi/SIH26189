def test_health_check(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


def test_upload_and_full_analysis_flow(client, small_case):
    r = client.post("/api/cases/upload", json=small_case)
    assert r.status_code == 200
    case_id = r.get_json()["case_id"]
    assert case_id == "TEST-CASE"

    r = client.get(f"/api/cases/{case_id}/graph")
    assert r.status_code == 200
    assert len(r.get_json()["nodes"]) == 4

    r = client.get(f"/api/cases/{case_id}/centrality")
    assert r.status_code == 200
    assert len(r.get_json()) == 4

    r = client.get(f"/api/cases/{case_id}/communities")
    assert r.status_code == 200

    r = client.get(f"/api/cases/{case_id}/anomalies")
    assert r.status_code == 200

    r = client.get(f"/api/cases/{case_id}/link-predictions")
    assert r.status_code == 200

    r = client.get(f"/api/cases/{case_id}/timeline")
    assert r.status_code == 200
    assert len(r.get_json()) == 5


def test_upload_rejects_missing_keys(client):
    r = client.post("/api/cases/upload", json={"entities": []})
    assert r.status_code == 400
    assert "error" in r.get_json()


def test_upload_rejects_empty_entities(client):
    r = client.post("/api/cases/upload", json={"entities": [], "artifacts": []})
    assert r.status_code == 400


def test_upload_rejects_non_json_body(client):
    r = client.post("/api/cases/upload", data="not json", content_type="text/plain")
    assert r.status_code == 400


def test_upload_rejects_duplicate_entity_ids(client):
    payload = {
        "entities": [{"entity_id": "X"}, {"entity_id": "X"}],
        "artifacts": [],
    }
    r = client.post("/api/cases/upload", json=payload)
    assert r.status_code == 400


def test_analysis_endpoints_404_for_unknown_case(client):
    for path in ["graph", "centrality", "communities", "anomalies", "link-predictions", "timeline"]:
        r = client.get(f"/api/cases/DOES-NOT-EXIST/{path}")
        assert r.status_code == 404, f"{path} did not return 404"


def test_path_requires_both_params(client, small_case):
    client.post("/api/cases/upload", json=small_case)
    r = client.get("/api/cases/TEST-CASE/path?source=A")
    assert r.status_code == 400


def test_path_rejects_unknown_entity(client, small_case):
    client.post("/api/cases/upload", json=small_case)
    r = client.get("/api/cases/TEST-CASE/path?source=A&target=ZZZ")
    assert r.status_code == 400


def test_path_finds_valid_route(client, small_case):
    client.post("/api/cases/upload", json=small_case)
    r = client.get("/api/cases/TEST-CASE/path?source=A&target=C")
    assert r.status_code == 200
    data = r.get_json()
    assert data["path"][0] == "A"
    assert data["path"][-1] == "C"


def test_timeline_rejects_unknown_entity(client, small_case):
    client.post("/api/cases/upload", json=small_case)
    r = client.get("/api/cases/TEST-CASE/timeline?entity_id=ZZZ")
    assert r.status_code == 400


def test_pdf_export_returns_pdf_bytes(client, small_case):
    client.post("/api/cases/upload", json=small_case)
    r = client.get("/api/cases/TEST-CASE/export/report.pdf")
    assert r.status_code == 200
    assert r.mimetype == "application/pdf"
    assert r.data[:4] == b"%PDF"


def test_csv_exports_return_csv(client, small_case):
    client.post("/api/cases/upload", json=small_case)
    for endpoint in ["entities.csv", "artifacts.csv", "analysis.csv"]:
        r = client.get(f"/api/cases/TEST-CASE/export/{endpoint}")
        assert r.status_code == 200
        assert r.mimetype == "text/csv"


def test_audit_log_records_actions(client, small_case):
    client.post("/api/cases/upload", json=small_case)
    client.get("/api/cases/TEST-CASE/graph")
    client.get("/api/cases/TEST-CASE/centrality")
    r = client.get("/api/cases/TEST-CASE/log")
    assert r.status_code == 200
    actions = [entry["action"] for entry in r.get_json()]
    assert "case_loaded" in actions
    assert "graph_viewed" in actions
    assert "centrality_analysis_run" in actions


def test_load_demo_case_end_to_end(client):
    r = client.post("/api/cases/load-demo")
    assert r.status_code == 200
    case_id = r.get_json()["case_id"]

    r = client.get(f"/api/cases/{case_id}/graph")
    assert r.status_code == 200
    assert len(r.get_json()["nodes"]) > 0
