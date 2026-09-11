import datetime
import logging
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from app.models import Alert, AlertStatus
from app.security.audit import log_audit_event
from app.security.custody import log_custody_action

logger = logging.getLogger(__name__)

def create_alert(
    db: Session,
    case_id: str,
    alert_type: str,
    related_entities: Optional[List[str]] = None,
    source_module: str = "DETECTOR",
    reason: Optional[str] = None
) -> Alert:
    """
    Register a newly detected pattern alert.
    Strict PS 26189 rule: status MUST default to PENDING and cannot be confirmed without human action.
    """
    alert = Alert(
        case_id=case_id,
        alert_type=alert_type,
        related_entities=related_entities or [],
        source_module=source_module,
        reason=reason,
        status=AlertStatus.PENDING.value,
        detected_at=datetime.datetime.utcnow()
    )

    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert

def confirm_alert(
    db: Session,
    alert_id: int,
    reviewer_id: str,
    reviewer_role: str,
    notes: Optional[str] = None
) -> Alert:
    """
    Investigator action: Confirm an automated detection as an investigative finding.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise ValueError(f"Alert #{alert_id} not found.")

    alert.status = AlertStatus.CONFIRMED.value
    alert.reviewed_by = reviewer_id
    alert.reviewed_at = datetime.datetime.utcnow()
    alert.review_notes = notes or "Confirmed by investigator"

    db.commit()
    db.refresh(alert)

    # Log to audit ledger
    log_audit_event(
        db=db,
        action="CONFIRM_ALERT",
        user_id=reviewer_id,
        role=reviewer_role,
        resource=f"alert:{alert_id}",
        details={"case_id": alert.case_id, "alert_type": alert.alert_type, "notes": notes}
    )

    # Log to Digital Chain of Custody
    log_custody_action(
        db=db,
        case_id=alert.case_id,
        action="ALERT_CONFIRMED",
        details={
            "alert_id": alert.id,
            "alert_type": alert.alert_type,
            "reviewer": reviewer_id,
            "notes": notes
        },
        user_id=reviewer_id,
        role=reviewer_role,
        source_id=f"alert:{alert_id}"
    )

    return alert

def dismiss_alert(
    db: Session,
    alert_id: int,
    reviewer_id: str,
    reviewer_role: str,
    notes: Optional[str] = None
) -> Alert:
    """
    Investigator action: Dismiss an alert as a false positive or benign activity.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise ValueError(f"Alert #{alert_id} not found.")

    alert.status = AlertStatus.DISMISSED.value
    alert.reviewed_by = reviewer_id
    alert.reviewed_at = datetime.datetime.utcnow()
    alert.review_notes = notes or "Dismissed by investigator (false positive)"

    db.commit()
    db.refresh(alert)

    # Log to audit ledger
    log_audit_event(
        db=db,
        action="DISMISS_ALERT",
        user_id=reviewer_id,
        role=reviewer_role,
        resource=f"alert:{alert_id}",
        details={"case_id": alert.case_id, "alert_type": alert.alert_type, "notes": notes}
    )

    # Log to Digital Chain of Custody
    log_custody_action(
        db=db,
        case_id=alert.case_id,
        action="ALERT_DISMISSED",
        details={
            "alert_id": alert.id,
            "alert_type": alert.alert_type,
            "reviewer": reviewer_id,
            "notes": notes
        },
        user_id=reviewer_id,
        role=reviewer_role,
        source_id=f"alert:{alert_id}"
    )

    return alert

def list_alerts(
    db: Session,
    case_id: Optional[str] = None,
    status_filter: Optional[str] = None,
    page: int = 1,
    page_size: int = 50
) -> Dict[str, Any]:
    """List alerts with filtering and pagination."""
    query = db.query(Alert)
    if case_id:
        query = query.filter(Alert.case_id == case_id)
    if status_filter:
        statuses = [s.strip().upper() for s in status_filter.split(",") if s.strip()]
        query = query.filter(Alert.status.in_(statuses))

    total = query.count()
    alerts = query.order_by(Alert.detected_at.desc()).offset((page - 1) * page_size).limit(page_size).all()

    items = []
    for a in alerts:
        items.append({
            "id": a.id,
            "case_id": a.case_id,
            "alert_type": a.alert_type,
            "related_entities": a.related_entities,
            "source_module": a.source_module,
            "reason": a.reason,
            "status": a.status,
            "detected_at": a.detected_at.isoformat() if a.detected_at else None,
            "reviewed_by": a.reviewed_by,
            "reviewed_at": a.reviewed_at.isoformat() if a.reviewed_at else None,
            "review_notes": a.review_notes
        })

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size
    }
