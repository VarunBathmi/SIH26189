import datetime
import logging
from typing import Optional, Any
from sqlalchemy.orm import Session
from app.models import AuditLog

logger = logging.getLogger(__name__)

def log_audit_event(
    db: Session,
    action: str,
    user_id: Optional[str] = None,
    role: Optional[str] = None,
    resource: Optional[str] = None,
    status: str = "SUCCESS",
    details: Optional[Any] = None,
    ip_address: Optional[str] = None
) -> AuditLog:
    """
    Append an immutable event to the audit ledger.
    """
    try:
        event = AuditLog(
            timestamp=datetime.datetime.utcnow(),
            user_id=str(user_id) if user_id else "SYSTEM",
            role=str(role) if role else "SYSTEM",
            action=action,
            resource=resource,
            status=status,
            details=details if isinstance(details, (dict, list)) else {"message": str(details)} if details else None,
            ip_address=ip_address
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to write audit log event: {e}")
        raise e
