import pytest
from sqlalchemy.orm import Session
from app.evidence.hash_engine import (
    generate_sha256,
    verify_sha256,
    format_hash_blocks,
    generate_visual_symbols
)
from app.evidence.service import register_evidence, verify_evidence_integrity
from app.models import EvidenceRecord, IntegrityStatus

def test_sha256_known_test_vectors():
    # 1. Empty string vector
    empty_bytes = b""
    expected_empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert generate_sha256(empty_bytes) == expected_empty

    # 2. Known string vector "abc"
    abc_bytes = b"abc"
    expected_abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert generate_sha256(abc_bytes) == expected_abc

def test_sha256_verification_and_tampering():
    original_data = b"CONFIDENTIAL CALL DETAIL RECORD 2026-09-10"
    original_hash = generate_sha256(original_data)

    # Identical bytes -> True
    assert verify_sha256(original_data, original_hash) is True

    # 1-byte alteration -> False
    tampered_data = b"CONFIDENTIAL CALL DETAIL RECORD 2026-09-11"
    assert verify_sha256(tampered_data, original_hash) is False

def test_visual_symbol_determinism():
    test_hash = "c6d499dca525805211a11b3e40334d5c32a0ff1f1c2dacc4bb591f3dae8a3e27"
    blocks = format_hash_blocks(test_hash)
    symbols = generate_visual_symbols(test_hash)

    assert "C6D4 99DC" in blocks
    assert len(symbols.split()) == 16 # 16 symbol groups

    # Re-running produces identical deterministic output
    assert generate_visual_symbols(test_hash) == symbols

def test_evidence_service_lifecycle(db_session: Session):
    case_id = "CASE-EV-TEST"
    file_bytes = b"%PDF-1.4 Mock Seized Forensic Evidence PDF Document Data"
    
    # 1. Register evidence
    ev = register_evidence(
        db=db_session,
        case_id=case_id,
        file_name="seized_phone_dump.pdf",
        file_bytes=file_bytes,
        file_type="PDF",
        actor_id="officer_sharma@investigation.gov.in"
    )

    assert ev.evidence_id.startswith("EV-")
    assert ev.integrity_status == IntegrityStatus.VERIFIED.value
    assert len(ev.sha256_hash) == 64

    # 2. Verify on-demand
    verify_result = verify_evidence_integrity(
        db=db_session,
        evidence_id=ev.evidence_id,
        actor_id="officer_sharma@investigation.gov.in"
    )
    assert verify_result["integrity_status"] == IntegrityStatus.VERIFIED.value
    assert verify_result["match"] is True

    # 3. Simulate file modification on disk
    with open(ev.storage_path, "wb") as f:
        f.write(b"TAMPERED EVIDENCE BYTES")

    tampered_verify = verify_evidence_integrity(
        db=db_session,
        evidence_id=ev.evidence_id,
        actor_id="officer_sharma@investigation.gov.in"
    )
    assert tampered_verify["integrity_status"] == IntegrityStatus.COMPROMISED.value
    assert tampered_verify["match"] is False
    # Original hash is preserved
    assert tampered_verify["original_hash"] == ev.sha256_hash
