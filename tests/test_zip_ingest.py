import io
import json
import zipfile
import pytest
from fastapi.testclient import TestClient

def _create_test_zip(files_dict: dict) -> bytes:
    """Create in-memory ZIP archive from a dictionary of filename -> content string/bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for fname, content in files_dict.items():
            if isinstance(content, str):
                z.writestr(fname, content.encode("utf-8"))
            else:
                z.writestr(fname, content)
    return buf.getvalue()

def test_zip_ingestion_valid_archive(client: TestClient, investigator_headers: dict):
    case_id = "CASE-ZIP-TEST-001"
    files = {
        "case_meta.json": json.dumps({"case_id": case_id, "title": "Operation Cyber Vault", "note": "Forensic dump from seized devices"}),
        "entities.csv": (
            "entity_id,name,phone,device_id,ip\n"
            "E-01,Vikram Malhotra,9876543210,DEV-991,192.168.1.50\n"
            "E-02,Suresh Raina,9811002233,DEV-992,10.0.0.12\n"
            "E-03,Rohan Sharma,9822334455,DEV-993,172.16.0.4\n"
        ),
        "calls.csv": (
            "caller_id,callee_id,duration_sec,timestamp\n"
            "E-01,E-02,320,2026-03-12T14:30:00\n"
            "E-02,E-03,150,2026-03-12T15:45:00\n"
        ),
        "chats.csv": (
            "sender_id,receiver_id,platform,timestamp,message\n"
            "E-01,E-03,Signal,2026-03-12T16:00:00,Consignment ready at Cyber Hub\n"
        ),
        "locations.csv": (
            "entity_id,lat,lng,timestamp\n"
            "E-01,28.4595,77.0266,2026-03-12T14:30:00\n"
            "E-02,28.4590,77.0270,2026-03-12T14:35:00\n"
        ),
        "fir.txt": "FIR Case Narrative: Intercepted communications regarding illicit cash handling in NCR."
    }

    zip_bytes = _create_test_zip(files)

    response = client.post(
        "/api/cases/upload-zip",
        headers=investigator_headers,
        files={"file": ("forensic_dump.zip", zip_bytes, "application/zip")}
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert data["case_id"] == case_id
    assert data["entity_count"] >= 3
    assert data["artifact_count"] >= 3
    assert "file_hashes" in data
    assert len(data["file_hashes"]) >= 5
    assert data["has_fir_text"] is True

    # Verify graph retrieval
    graph_res = client.get(f"/api/cases/{case_id}/graph?source=neo4j", headers=investigator_headers)
    assert graph_res.status_code == 200
    graph_data = graph_res.json()
    assert len(graph_data["nodes"]) >= 3
    assert len(graph_data["links"]) >= 3

def test_zip_ingestion_no_forensic_files_error(client: TestClient, investigator_headers: dict):
    # Zip containing only random unparsed files
    files = {
        "readme.txt": "This archive has no forensic tables.",
        "random_image.bin": b"\x00\x01\x02\x03\x04"
    }
    zip_bytes = _create_test_zip(files)

    response = client.post(
        "/api/cases/upload-zip",
        headers=investigator_headers,
        files={"file": ("empty_forensics.zip", zip_bytes, "application/zip")}
    )

    assert response.status_code == 400
    assert "No forensic data files found" in response.json()["detail"]

def test_zip_ingestion_partial_data_with_warnings(client: TestClient, investigator_headers: dict):
    # Calls CSV has 1 valid row and 1 malformed row without callee
    files = {
        "calls.csv": (
            "caller,callee,duration_sec,timestamp\n"
            "Suspect_A,Suspect_B,120,2026-01-01T10:00:00\n"
            "Suspect_C,,400,2026-01-01T11:00:00\n" # Missing callee
        )
    }
    zip_bytes = _create_test_zip(files)

    response = client.post(
        "/api/cases/upload-zip",
        headers=investigator_headers,
        files={"file": ("partial_dump.zip", zip_bytes, "application/zip")}
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert data["artifact_count"] >= 1
    assert len(data["warnings"]) >= 1
    assert any("missing" in w.lower() for w in data["warnings"])

def test_zip_ingestion_corrupt_file_error(client: TestClient, investigator_headers: dict):
    # Random non-zip bytes
    corrupt_bytes = b"NOT_A_VALID_ZIP_HEADER_DATA"

    response = client.post(
        "/api/cases/upload-zip",
        headers=investigator_headers,
        files={"file": ("corrupt.zip", corrupt_bytes, "application/zip")}
    )

    assert response.status_code == 400
    assert "invalid" in response.json()["detail"].lower() or "corrupt" in response.json()["detail"].lower()

def test_zip_ingestion_password_protected_error(client: TestClient, investigator_headers: dict):
    # Create encrypted ZIP
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.setpassword(b"secret123")
        # Write file with password flag
        z.writestr("calls.csv", "caller,callee,timestamp\nA,B,2026-01-01")
        # Note: In standard python zipfile writestr doesn't encrypt unless using a third party tool or setpassword with writestr
        # Let's set flag_bits bit 0 on zipinfo to simulate encrypted zip entry
        for zinfo in z.filelist:
            zinfo.flag_bits |= 0x1

    response = client.post(
        "/api/cases/upload-zip",
        headers=investigator_headers,
        files={"file": ("encrypted.zip", buf.getvalue(), "application/zip")}
    )

    assert response.status_code == 400
    assert "password" in response.json()["detail"].lower() or "encrypt" in response.json()["detail"].lower()

def test_zip_ingestion_oversized_guard(client: TestClient, investigator_headers: dict):
    # Mock zipinfo with oversized declared file_size
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("huge_file.csv", "a" * 100)
        for zinfo in z.filelist:
            zinfo.file_size = 300 * 1024 * 1024 # 300 MB > 200MB cap

    response = client.post(
        "/api/cases/upload-zip",
        headers=investigator_headers,
        files={"file": ("zipbomb.zip", buf.getvalue(), "application/zip")}
    )

    assert response.status_code == 400
    assert "exceeds" in response.json()["detail"].lower() or "limit" in response.json()["detail"].lower()

def test_zip_ingestion_temp_dir_cleanup_and_sha256(client: TestClient, investigator_headers: dict):
    import tempfile
    import os
    from app.evidence.hash_engine import generate_sha256

    content = "caller_id,callee_id,timestamp\nX,Y,2026-01-01T10:00:00\n"
    expected_hash = generate_sha256(content.encode("utf-8"))
    files = {"calls.csv": content}
    zip_bytes = _create_test_zip(files)

    # Check temp dirs before
    temp_root = tempfile.gettempdir()
    before_dirs = set(os.listdir(temp_root))

    response = client.post(
        "/api/cases/upload-zip",
        headers=investigator_headers,
        files={"file": ("cleanup_test.zip", zip_bytes, "application/zip")}
    )

    assert response.status_code == 200
    data = response.json()
    assert data["file_hashes"]["calls.csv"] == expected_hash

    # Check temp dirs after - no leftover sih_forensic_zip_ directory
    after_dirs = set(os.listdir(temp_root))
    new_sih_dirs = [d for d in (after_dirs - before_dirs) if d.startswith("sih_forensic_zip_")]
    assert len(new_sih_dirs) == 0, f"Temporary directories were not cleaned up: {new_sih_dirs}"
