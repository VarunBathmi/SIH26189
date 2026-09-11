import pytest
from sqlalchemy.orm import Session
from app.models import CustodyLog
from app.security.custody import (
    log_custody_action,
    verify_custody_chain,
    get_latest_case_hash,
    GENESIS_PREV_HASH
)

def test_custody_hash_chain_creation_and_verification(db_session: Session):
    case_id = "CASE-TEST-001"
    
    # 1. Initial state -> genesis hash
    initial_hash = get_latest_case_hash(db_session, case_id)
    assert initial_hash == GENESIS_PREV_HASH

    # 2. Log several sequential actions
    rec1 = log_custody_action(
        db=db_session,
        case_id=case_id,
        action="CASE_CREATED",
        details={"title": "Operation Cyber Shield"},
        user_id="inspector@investigation.gov.in",
        role="INVESTIGATOR"
    )
    assert rec1.previous_hash == GENESIS_PREV_HASH
    assert len(rec1.current_hash) == 64

    rec2 = log_custody_action(
        db=db_session,
        case_id=case_id,
        action="RAW_REPORT_STORED",
        details={"doc_id": "FIR-001"},
        user_id="inspector@investigation.gov.in",
        role="INVESTIGATOR"
    )
    assert rec2.previous_hash == rec1.current_hash

    rec3 = log_custody_action(
        db=db_session,
        case_id=case_id,
        action="NLP_ANALYSIS_COMPLETED",
        details={"entities_count": 5},
        user_id="inspector@investigation.gov.in",
        role="INVESTIGATOR"
    )
    assert rec3.previous_hash == rec2.current_hash

    # 3. Verify valid chain
    verify_res = verify_custody_chain(db_session, case_id)
    assert verify_res["chain_valid"] is True
    assert verify_res["records_checked"] == 3
    assert verify_res["first_hash"] == rec1.current_hash
    assert verify_res["latest_hash"] == rec3.current_hash
    assert len(verify_res["errors"]) == 0

def test_custody_tamper_detection(db_session: Session):
    case_id = "CASE-TAMPER-TEST"

    # Create 2 records
    rec1 = log_custody_action(db=db_session, case_id=case_id, action="CASE_CREATED", details={"t": 1})
    rec2 = log_custody_action(db=db_session, case_id=case_id, action="EVIDENCE_UPLOADED", details={"t": 2})

    # Tamper with rec1's current_hash directly in DB
    rec1.current_hash = "f" * 64
    db_session.commit()

    # Verification must detect the tampering
    verify_res = verify_custody_chain(db_session, case_id)
    assert verify_res["chain_valid"] is False
    assert len(verify_res["errors"]) > 0
