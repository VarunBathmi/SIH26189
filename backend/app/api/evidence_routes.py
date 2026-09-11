from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import UserRole, EvidenceRecord, CustodyLog
from app.security.auth import get_current_user, require_role
from app.evidence.service import (
    register_evidence,
    verify_evidence_integrity
)

router = APIRouter(prefix="/api", tags=["Digital Evidence Cryptographic Integrity (SHA-256)"])

@router.post("/evidence/upload", summary="Upload digital evidence and compute immutable SHA-256 cryptographic fingerprint")
async def upload_evidence(
    file: UploadFile = File(...),
    case_id: str = Form(...),
    current_user: dict = Depends(require_role([UserRole.INVESTIGATOR, UserRole.ADMINISTRATOR])),
    db: Session = Depends(get_db)
):
    try:
        file_bytes = await file.read()
        actor = current_user.get("email", "INVESTIGATOR")
        role = current_user.get("role", "INVESTIGATOR")

        record = register_evidence(
            db=db,
            case_id=case_id.strip(),
            file_name=file.filename or "evidence.bin",
            file_bytes=file_bytes,
            actor_id=actor,
            role=role
        )

        return {
            "evidence_id": record.evidence_id,
            "case_id": record.case_id,
            "file_name": record.file_name,
            "file_type": record.file_type,
            "file_size_bytes": record.file_size,
            "algorithm": record.hash_algorithm,
            "sha256_fingerprint": record.sha256_hash,
            "visual_blocks": record.visual_blocks,
            "visual_symbols": record.visual_symbols,
            "integrity_status": record.integrity_status,
            "hash_created_at": record.hash_created_at.isoformat() if record.hash_created_at else None,
            "message": "Digital evidence registered and cryptographic fingerprint recorded in custody chain."
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to register evidence: {str(e)}")

@router.get("/evidence/{evidence_id}", summary="Retrieve evidence profile, cryptographic hash, and visual fingerprint")
def get_evidence(
    evidence_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    record = db.query(EvidenceRecord).filter(EvidenceRecord.evidence_id == evidence_id).first()
    if not record:
        raise HTTPException(status_code=404, detail=f"Evidence with ID '{evidence_id}' not found.")

    return {
        "evidence_id": record.evidence_id,
        "case_id": record.case_id,
        "file_name": record.file_name,
        "file_type": record.file_type,
        "file_size_bytes": record.file_size,
        "algorithm": record.hash_algorithm,
        "sha256_fingerprint": record.sha256_hash,
        "visual_blocks": record.visual_blocks,
        "visual_symbols": record.visual_symbols,
        "integrity_status": record.integrity_status,
        "hash_created_at": record.hash_created_at.isoformat() if record.hash_created_at else None,
        "created_at": record.created_at.isoformat() if record.created_at else None
    }

@router.get("/evidence/{evidence_id}/hash", summary="Retrieve SHA-256 fingerprint of evidence artifact")
def get_evidence_hash(
    evidence_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    record = db.query(EvidenceRecord).filter(EvidenceRecord.evidence_id == evidence_id).first()
    if not record:
        raise HTTPException(status_code=404, detail=f"Evidence with ID '{evidence_id}' not found.")

    return {
        "evidence_id": record.evidence_id,
        "algorithm": record.hash_algorithm,
        "sha256_fingerprint": record.sha256_hash,
        "file_name": record.file_name
    }

@router.post("/evidence/{evidence_id}/verify", summary="Verify stored evidence binary bytes against recorded SHA-256 fingerprint")
def verify_evidence(
    evidence_id: str,
    current_user: dict = Depends(require_role([UserRole.INVESTIGATOR, UserRole.ADMINISTRATOR])),
    db: Session = Depends(get_db)
):
    try:
        actor = current_user.get("email", "INVESTIGATOR")
        role = current_user.get("role", "INVESTIGATOR")
        result = verify_evidence_integrity(
            db=db,
            evidence_id=evidence_id,
            actor_id=actor,
            role=role
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification error: {str(e)}")

@router.get("/evidence/{evidence_id}/custody", summary="Retrieve chain of custody history for specific evidence artifact")
def get_evidence_custody(
    evidence_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    records = (
        db.query(CustodyLog)
        .filter(CustodyLog.source_id == evidence_id)
        .order_by(CustodyLog.id.asc())
        .all()
    )
    items = []
    for r in records:
        items.append({
            "id": r.id,
            "case_id": r.case_id,
            "action": r.action,
            "details": r.details,
            "previous_hash": r.previous_hash,
            "current_hash": r.current_hash,
            "user_id": r.user_id,
            "timestamp": r.created_at.isoformat() if r.created_at else None
        })
    return {
        "evidence_id": evidence_id,
        "total_custody_events": len(items),
        "events": items
    }

@router.get("/cases/{case_id}/evidence", summary="List all digital evidence registered under a case")
def list_case_evidence(
    case_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    evidence_list = (
        db.query(EvidenceRecord)
        .filter(EvidenceRecord.case_id == case_id)
        .order_by(EvidenceRecord.created_at.desc())
        .all()
    )
    items = []
    for ev in evidence_list:
        items.append({
            "evidence_id": ev.evidence_id,
            "file_name": ev.file_name,
            "file_type": ev.file_type,
            "file_size": ev.file_size,
            "algorithm": ev.hash_algorithm,
            "sha256_fingerprint": ev.sha256_hash,
            "integrity_status": ev.integrity_status,
            "visual_blocks": ev.visual_blocks,
            "visual_symbols": ev.visual_symbols,
            "created_at": ev.created_at.isoformat() if ev.created_at else None
        })
    return {
        "case_id": case_id,
        "total": len(items),
        "evidence": items
    }
