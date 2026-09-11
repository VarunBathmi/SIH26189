import pytest
from fastapi.testclient import TestClient

def test_api_health(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ("healthy", "degraded")
    assert "database" in data
    assert "neo4j" in data

def test_full_investigation_workflow_api(
    client: TestClient,
    investigator_headers: dict,
    admin_headers: dict
):
    case_id = "CASE-API-001"

    # 1. Create Case
    case_res = client.post(
        "/cases",
        headers=investigator_headers,
        json={"case_id": case_id, "title": "National Security Investigation 2026"}
    )
    assert case_res.status_code == 200

    # 2. Ingest Raw Investigation Narrative Report
    report_text = (
        "Rohan Sharma, director at Shakti Traders, called Vikas Yadav for 15 minutes at 11:30 PM on 5th January. "
        "On 6th January around 4 PM, Rohan Sharma transferred ₹45,000 to Vikas Yadav near Sector 22 market State Bank branch. "
        "Vehicle DL-01-AB-1234 was used by Rohan."
    )
    ingest_res = client.post(
        "/ingestion/report",
        headers=investigator_headers,
        json={
            "document_id": "FIR-2026-901",
            "document_type": "FIR",
            "case_id": case_id,
            "text": report_text
        }
    )
    assert ingest_res.status_code == 200
    ingest_data = ingest_res.json()
    assert "graph_delta" in ingest_data
    assert len(ingest_data["graph_delta"]["nodes_added"]) >= 2
    assert "disclaimer" in ingest_data

    # 3. Verify Chain of Custody
    custody_res = client.get(f"/api/v1/cases/{case_id}/custody/verify", headers=investigator_headers)
    assert custody_res.status_code == 200
    custody_data = custody_res.json()
    assert custody_data["chain_valid"] is True
    assert custody_data["records_checked"] >= 3

    # 4. Upload and Verify Digital Evidence
    upload_res = client.post(
        "/api/evidence/upload",
        headers=investigator_headers,
        data={"case_id": case_id},
        files={"file": ("intercepted_log.txt", b"CALL LOG DATA 9876543210 -> 9811111111", "text/plain")}
    )
    assert upload_res.status_code == 200
    ev_data = upload_res.json()
    evidence_id = ev_data["evidence_id"]
    assert ev_data["integrity_status"] == "VERIFIED"
    assert "visual_symbols" in ev_data

    # Verify evidence on demand
    verify_res = client.post(f"/api/evidence/{evidence_id}/verify", headers=investigator_headers)
    assert verify_res.status_code == 200
    assert verify_res.json()["integrity_status"] == "VERIFIED"

    # 5. Review and Confirm Alert
    alerts_res = client.get(f"/alerts?case_id={case_id}", headers=investigator_headers)
    assert alerts_res.status_code == 200
    alerts_items = alerts_res.json()["items"]
    if alerts_items:
        alert_id = alerts_items[0]["id"]
        confirm_res = client.post(
            f"/alerts/{alert_id}/confirm",
            headers=investigator_headers,
            json={"notes": "Investigator confirmed CDR correlation"}
        )
        assert confirm_res.status_code == 200
        assert confirm_res.json()["status"] == "CONFIRMED"

    # 6. Dual-Authorization Reveal Request Workflow
    # Extract hash_id for Rohan Sharma
    nodes = ingest_data["graph_delta"]["nodes_added"]
    person_node = [n for n in nodes if n["type"] == "Person"][0]
    hash_id = person_node["id"]

    # Submit reveal request
    req_res = client.post(
        "/secure/reveal-request",
        headers=investigator_headers,
        json={"hash_id": hash_id, "case_id": case_id, "reason": "Court-authorized warrant #9982"}
    )
    assert req_res.status_code == 200
    request_id = req_res.json()["request_id"]

    # Creator self-approval must be blocked
    self_approve = client.post(f"/secure/reveal-request/{request_id}/approve", headers=investigator_headers)
    assert self_approve.status_code == 403

    # Admin approval
    admin_approve = client.post(f"/secure/reveal-request/{request_id}/approve", headers=admin_headers)
    assert admin_approve.status_code == 200

    # Distinct Investigator approval
    second_inv_headers = {"X-Role": "investigator", "X-User": "second_officer@investigation.gov.in"}
    inv_approve = client.post(f"/secure/reveal-request/{request_id}/approve", headers=second_inv_headers)
    assert inv_approve.status_code == 200
    assert inv_approve.json()["status"] == "APPROVED"

    # Fetch status with decrypted name
    status_res = client.get(f"/secure/reveal-request/{request_id}", headers=investigator_headers)
    assert status_res.status_code == 200
    assert "real_name" in status_res.json()
    assert status_res.json()["real_name"] in ("Rohan Sharma", "Vikas Yadav")
