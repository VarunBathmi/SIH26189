import json
import hashlib
import datetime
import logging
from typing import Optional, Any, List, Dict
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.models import CustodyLog

logger = logging.getLogger(__name__)

GENESIS_PREV_HASH = "0" * 64

def compute_custody_hash(case_id: str, action: str, details: Any, prev_hash: str, timestamp_iso: str) -> str:
    """
    Compute canonical SHA-256 hash for a chain of custody record.
    Uses canonical JSON sorting to ensure exact deterministic hashing.
    """
    payload = {
        "case_id": case_id,
        "action": action,
        "details": details,
        "prev": prev_hash,
        "time": timestamp_iso
    }
    canonical_json = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

def get_latest_case_hash(db: Session, case_id: str) -> str:
    """
    Get the latest current_hash for the given case_id.
    Returns '0'*64 if no records exist.
    """
    latest_record = (
        db.query(CustodyLog)
        .filter(CustodyLog.case_id == case_id)
        .order_by(desc(CustodyLog.id))
        .first()
    )
    if latest_record and latest_record.current_hash:
        return latest_record.current_hash
    return GENESIS_PREV_HASH

def log_custody_action(
    db: Session,
    case_id: str,
    action: str,
    details: Optional[Any] = None,
    user_id: Optional[str] = None,
    role: Optional[str] = None,
    source_id: Optional[str] = None,
    entity_id: Optional[str] = None,
    relationship_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    request_id: Optional[str] = None
) -> CustodyLog:
    """
    Append an immutable, verifiable record to the Digital Chain of Custody.
    Calculates previous_hash and generates new cryptographic current_hash.
    """
    try:
        prev_hash = get_latest_case_hash(db, case_id)
        now_dt = datetime.datetime.utcnow()
        timestamp_iso = now_dt.isoformat()

        # Canonicalize details for JSON storage
        details_val = details if isinstance(details, (dict, list)) else {"info": str(details)} if details is not None else {}

        current_hash = compute_custody_hash(
            case_id=case_id,
            action=action,
            details=details_val,
            prev_hash=prev_hash,
            timestamp_iso=timestamp_iso
        )

        record = CustodyLog(
            case_id=case_id,
            action=action,
            details=details_val,
            previous_hash=prev_hash,
            current_hash=current_hash,
            user_id=user_id or "SYSTEM",
            role=role or "SYSTEM",
            source_id=source_id,
            entity_id=entity_id,
            relationship_id=relationship_id,
            ip_address=ip_address,
            request_id=request_id,
            created_at=now_dt
        )

        db.add(record)
        db.commit()
        db.refresh(record)
        return record
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to log custody action: {e}")
        raise e

def verify_custody_chain(db: Session, case_id: str) -> Dict[str, Any]:
    """
    Verify the integrity of the Digital Chain of Custody for a specific case.
    Validates chronological link consistency and recomputes hashes.
    """
    records: List[CustodyLog] = (
        db.query(CustodyLog)
        .filter(CustodyLog.case_id == case_id)
        .order_by(CustodyLog.id.asc())
        .all()
    )

    if not records:
        return {
            "case_id": case_id,
            "chain_valid": True,
            "records_checked": 0,
            "first_hash": None,
            "latest_hash": None,
            "errors": []
        }

    errors = []
    expected_prev = GENESIS_PREV_HASH

    for idx, rec in enumerate(records):
        # 1. Check previous hash continuity
        if rec.previous_hash != expected_prev:
            errors.append({
                "record_id": rec.id,
                "action": rec.action,
                "reason": f"Previous hash mismatch at step {idx}. Expected {expected_prev}, found {rec.previous_hash}"
            })

        # 2. Re-compute hash from immutable stored fields
        timestamp_iso = rec.created_at.isoformat()
        recalculated_hash = compute_custody_hash(
            case_id=rec.case_id,
            action=rec.action,
            details=rec.details,
            prev_hash=rec.previous_hash,
            timestamp_iso=timestamp_iso
        )

        if recalculated_hash != rec.current_hash:
            errors.append({
                "record_id": rec.id,
                "action": rec.action,
                "reason": f"Record hash mismatch. Stored: {rec.current_hash}, Recalculated: {recalculated_hash}"
            })

        # Next link expects this record's current_hash
        expected_prev = rec.current_hash

    is_valid = len(errors) == 0

    return {
        "case_id": case_id,
        "chain_valid": is_valid,
        "records_checked": len(records),
        "first_hash": records[0].current_hash,
        "latest_hash": records[-1].current_hash,
        "errors": errors
    }
