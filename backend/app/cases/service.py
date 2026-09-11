import datetime
import logging
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from app.models import CaseRecord, CaseStatus, DocumentRecord, EvidenceRecord, Alert
from app.security.custody import log_custody_action
from app.security.audit import log_audit_event

logger = logging.getLogger(__name__)

def create_case(
    db: Session,
    case_id: str,
    title: str,
    description: Optional[str] = None,
    case_number: Optional[str] = None,
    created_by: Optional[str] = "INVESTIGATOR"
) -> CaseRecord:
    """Create a new criminal investigation case record and initialize chain of custody."""
    existing = db.query(CaseRecord).filter(CaseRecord.case_id == case_id).first()
    if existing:
        raise ValueError(f"Case with ID '{case_id}' already exists.")

    case = CaseRecord(
        case_id=case_id,
        case_number=case_number or case_id,
        title=title,
        description=description,
        status=CaseStatus.OPEN.value,
        created_by=created_by,
        created_at=datetime.datetime.utcnow(),
        updated_at=datetime.datetime.utcnow()
    )

    db.add(case)
    db.commit()
    db.refresh(case)

    # Initialize Digital Chain of Custody
    log_custody_action(
        db=db,
        case_id=case_id,
        action="CASE_CREATED",
        details={
            "case_id": case_id,
            "title": title,
            "case_number": case_number,
            "created_by": created_by
        },
        user_id=created_by,
        role="INVESTIGATOR"
    )

    # Audit log
    log_audit_event(
        db=db,
        action="CREATE_CASE",
        user_id=created_by,
        resource=f"case:{case_id}",
        details={"title": title}
    )

    return case

def get_case_detail(db: Session, case_id: str) -> Dict[str, Any]:
    """Get case details including summary counts of documents, evidence, and alerts."""
    case = db.query(CaseRecord).filter(CaseRecord.case_id == case_id).first()
    if not case:
        raise ValueError(f"Case '{case_id}' not found.")

    doc_count = db.query(DocumentRecord).filter(DocumentRecord.case_id == case_id).count()
    evidence_count = db.query(EvidenceRecord).filter(EvidenceRecord.case_id == case_id).count()
    alert_count = db.query(Alert).filter(Alert.case_id == case_id).count()
    pending_alerts = db.query(Alert).filter(Alert.case_id == case_id, Alert.status == "PENDING").count()

    return {
        "case_id": case.case_id,
        "case_number": case.case_number,
        "title": case.title,
        "description": case.description,
        "status": case.status,
        "created_by": case.created_by,
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "updated_at": case.updated_at.isoformat() if case.updated_at else None,
        "summary": {
            "documents_count": doc_count,
            "evidence_count": evidence_count,
            "total_alerts": alert_count,
            "pending_alerts": pending_alerts
        }
    }

def update_case_status(
    db: Session,
    case_id: str,
    new_status: str,
    actor_id: str = "INVESTIGATOR",
    role: str = "INVESTIGATOR"
) -> CaseRecord:
    """Update case status lifecycle (OPEN, IN_PROGRESS, COMPLETED, CLOSED)."""
    case = db.query(CaseRecord).filter(CaseRecord.case_id == case_id).first()
    if not case:
        raise ValueError(f"Case '{case_id}' not found.")

    valid_statuses = [s.value for s in CaseStatus]
    status_upper = new_status.strip().upper()
    if status_upper not in valid_statuses:
        raise ValueError(f"Invalid status '{new_status}'. Allowed: {valid_statuses}")

    old_status = case.status
    case.status = status_upper
    case.updated_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(case)

    action_name = "CASE_COMPLETED" if status_upper == "COMPLETED" else "CASE_UPDATED"
    log_custody_action(
        db=db,
        case_id=case_id,
        action=action_name,
        details={"old_status": old_status, "new_status": status_upper},
        user_id=actor_id,
        role=role
    )

    log_audit_event(
        db=db,
        action="UPDATE_CASE_STATUS",
        user_id=actor_id,
        role=role,
        resource=f"case:{case_id}",
        details={"old_status": old_status, "new_status": status_upper}
    )

    return case

def list_cases(
    db: Session,
    status_filter: Optional[str] = None,
    page: int = 1,
    page_size: int = 50
) -> Dict[str, Any]:
    """List cases with optional status filtering and pagination."""
    query = db.query(CaseRecord)
    if status_filter:
        statuses = [s.strip().upper() for s in status_filter.split(",") if s.strip()]
        query = query.filter(CaseRecord.status.in_(statuses))

    total = query.count()
    cases = query.order_by(CaseRecord.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()

    items = []
    for c in cases:
        items.append({
            "case_id": c.case_id,
            "case_number": c.case_number,
            "title": c.title,
            "description": c.description,
            "status": c.status,
            "created_by": c.created_by,
            "created_at": c.created_at.isoformat() if c.created_at else None
        })

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size
    }
