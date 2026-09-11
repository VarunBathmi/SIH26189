import os
import re
import uuid
import datetime
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from app.config import settings
from app.models import EvidenceRecord, IntegrityStatus
from app.evidence.hash_engine import (
    generate_sha256,
    verify_sha256,
    format_hash_blocks,
    generate_visual_symbols
)
from app.security.custody import log_custody_action

logger = logging.getLogger(__name__)

def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal and shell injection."""
    clean = Path(filename).name
    clean = re.sub(r'[^a-zA-Z0-9_.-]', '_', clean)
    return clean or "evidence_file.bin"

def register_evidence(
    db: Session,
    case_id: str,
    file_name: str,
    file_bytes: bytes,
    file_type: Optional[str] = None,
    actor_id: Optional[str] = "SYSTEM",
    role: Optional[str] = "INVESTIGATOR"
) -> EvidenceRecord:
    """
    Ingest a digital evidence file:
    1. Calculate binary SHA-256 cryptographic fingerprint
    2. Store file safely to disk
    3. Generate visual blocks and symbols
    4. Save EvidenceRecord to DB with status VERIFIED
    5. Append EVIDENCE_UPLOADED to Digital Chain of Custody
    """
    clean_name = sanitize_filename(file_name)
    sha_hash = generate_sha256(file_bytes)
    file_size = len(file_bytes)
    
    # Generate unique evidence ID
    evidence_id = f"EV-{uuid.uuid4().hex[:8].upper()}"
    
    # Save file safely
    case_evidence_dir = settings.EVIDENCE_STORAGE_DIR / case_id
    case_evidence_dir.mkdir(parents=True, exist_ok=True)
    saved_path = case_evidence_dir / f"{evidence_id}_{clean_name}"
    
    with open(saved_path, "wb") as f:
        f.write(file_bytes)

    # Determine file type if missing
    inferred_type = file_type or clean_name.split(".")[-1].upper() if "." in clean_name else "BIN"

    # Generate visual fingerprint
    blocks = format_hash_blocks(sha_hash)
    symbols = generate_visual_symbols(sha_hash)

    now_dt = datetime.datetime.utcnow()

    record = EvidenceRecord(
        evidence_id=evidence_id,
        case_id=case_id,
        file_name=clean_name,
        file_type=inferred_type,
        file_size=file_size,
        sha256_hash=sha_hash,
        hash_algorithm="SHA-256",
        hash_created_at=now_dt,
        integrity_status=IntegrityStatus.VERIFIED.value,
        storage_path=str(saved_path),
        visual_blocks=blocks,
        visual_symbols=symbols,
        metadata_json={
            "original_filename": file_name,
            "uploaded_by": actor_id,
            "role": role,
            "byte_size": file_size
        },
        created_at=now_dt
    )

    db.add(record)
    db.commit()
    db.refresh(record)

    # Append to Digital Chain of Custody
    log_custody_action(
        db=db,
        case_id=case_id,
        action="EVIDENCE_UPLOADED",
        details={
            "evidence_id": evidence_id,
            "file_name": clean_name,
            "sha256_hash": sha_hash,
            "file_size": file_size,
            "integrity_status": IntegrityStatus.VERIFIED.value
        },
        user_id=actor_id,
        role=role,
        source_id=evidence_id
    )

    return record

def verify_evidence_integrity(
    db: Session,
    evidence_id: str,
    actor_id: Optional[str] = "SYSTEM",
    role: Optional[str] = "INVESTIGATOR"
) -> Dict[str, Any]:
    """
    Locate stored evidence bytes on disk, recalculate SHA-256,
    and compare with the immutable originally recorded fingerprint.
    Updates status to VERIFIED or COMPROMISED without modifying the original hash.
    Logs to custody chain.
    """
    record = db.query(EvidenceRecord).filter(EvidenceRecord.evidence_id == evidence_id).first()
    if not record:
        raise ValueError(f"Evidence with ID '{evidence_id}' not found.")

    storage_path = Path(record.storage_path)
    if not storage_path.exists():
        record.integrity_status = IntegrityStatus.COMPROMISED.value
        db.commit()
        log_custody_action(
            db=db,
            case_id=record.case_id,
            action="EVIDENCE_FILE_MISSING",
            details={"evidence_id": evidence_id, "expected_path": str(storage_path)},
            user_id=actor_id,
            role=role,
            source_id=evidence_id
        )
        return {
            "evidence_id": evidence_id,
            "algorithm": "SHA-256",
            "original_hash": record.sha256_hash,
            "current_hash": None,
            "integrity_status": IntegrityStatus.COMPROMISED.value,
            "message": "Evidence file not found on disk storage",
            "verified_at": datetime.datetime.utcnow().isoformat()
        }

    with open(storage_path, "rb") as f:
        current_bytes = f.read()

    current_hash = generate_sha256(current_bytes)
    is_valid = verify_sha256(current_bytes, record.sha256_hash)

    status_str = IntegrityStatus.VERIFIED.value if is_valid else IntegrityStatus.COMPROMISED.value
    record.integrity_status = status_str
    db.commit()

    action_name = "EVIDENCE_VERIFIED" if is_valid else "EVIDENCE_COMPROMISED"
    log_custody_action(
        db=db,
        case_id=record.case_id,
        action=action_name,
        details={
            "evidence_id": evidence_id,
            "original_hash": record.sha256_hash,
            "current_hash": current_hash,
            "integrity_status": status_str,
            "match": is_valid
        },
        user_id=actor_id,
        role=role,
        source_id=evidence_id
    )

    return {
        "evidence_id": evidence_id,
        "case_id": record.case_id,
        "file_name": record.file_name,
        "algorithm": "SHA-256",
        "original_hash": record.sha256_hash,
        "current_hash": current_hash,
        "integrity_status": status_str,
        "match": is_valid,
        "visual_blocks": format_hash_blocks(current_hash),
        "visual_symbols": generate_visual_symbols(current_hash),
        "verified_at": datetime.datetime.utcnow().isoformat()
    }
