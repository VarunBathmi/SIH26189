import io
import zipfile
import pytest
from pathlib import Path
from app.forensics.zip_analyzer import analyze_and_extract_zip, check_case_provenance
from app.forensics.co_location import detect_co_locations, haversine_distance_meters
from app.forensics.report_generator import generate_case_pdf_dossier
from app.config import settings

def test_zip_analyzer_and_provenance():
    # Build in-memory mock zip
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as z:
        z.writestr("call_dump.json", '{"records": [{"caller": "A", "callee": "B", "case_id": "CASE-999"}]}')
        z.writestr("device_info.txt", "IMEI: 869402019482910")
    
    zip_bytes = zip_buffer.getvalue()
    extract_target = settings.EVIDENCE_STORAGE_DIR / "test_unpacked"

    parent_hash, children = analyze_and_extract_zip(zip_bytes, extract_target)
    assert len(parent_hash) == 64
    assert len(children) == 2

    # Check Provenance mismatch
    prov_mismatch = check_case_provenance("CASE-001", [{"record": {"case_id": "CASE-999"}}])
    assert prov_mismatch["case_id_match"] is False
    assert prov_mismatch["expected"] == "CASE-001"
    assert "CASE-999" in prov_mismatch["found"]

    # Check Provenance match
    prov_match = check_case_provenance("CASE-001", [{"record": {"case_id": "CASE-001"}}])
    assert prov_match["case_id_match"] is True

def test_co_location_detection():
    # Two points ~30 meters apart in Sector 22, Chandigarh
    locs = [
        {"person_name": "Rohan", "latitude": 30.7333, "longitude": 76.7794, "timestamp": "2026-01-05T23:40:00", "location_name": "Sector 22 Market"},
        {"person_name": "Vikas", "latitude": 30.7335, "longitude": 76.7796, "timestamp": "2026-01-05T23:42:00", "location_name": "Sector 22 Market"}
    ]
    co_locs = detect_co_locations(locs, distance_threshold_meters=100.0)
    assert len(co_locs) == 1
    assert co_locs[0]["distance_meters"] <= 100.0

def test_pdf_dossier_generation():
    case_data = {"case_id": "CASE-DOSSIER-TEST", "title": "Operation Cyber Audit", "status": "OPEN"}
    evidence_list = [
        {"evidence_id": "EV-001", "file_name": "call_dump.pdf", "file_type": "PDF", "sha256_hash": "c6d499dca525805211a11b3e40334d5c32a0ff1f1c2dacc4bb591f3dae8a3e27", "integrity_status": "VERIFIED"}
    ]
    custody_info = {
        "case_id": "CASE-DOSSIER-TEST", "chain_valid": True, "records_checked": 5, "first_hash": "0"*64, "latest_hash": "a"*64
    }
    graph_analytics = {
        "top_influencers": [{"label": "Rohan Sharma", "type": "Person", "pagerank": 0.35, "betweenness": 0.42, "priority_score": 88.5}]
    }
    alerts_list = [
        {"alert_type": "CALL_BURST", "reason": "3 repeated calls at 02:00 AM", "status": "CONFIRMED", "review_notes": "Verified by officer"}
    ]

    pdf_path = generate_case_pdf_dossier(
        case_data=case_data,
        evidence_list=evidence_list,
        custody_info=custody_info,
        graph_analytics=graph_analytics,
        alerts_list=alerts_list
    )
    assert pdf_path.exists()
    assert pdf_path.stat().st_size > 1000 # Valid non-empty PDF
