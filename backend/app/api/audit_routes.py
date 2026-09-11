from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import AuditLog, UserRole
from app.security.auth import require_role

router = APIRouter(prefix="/audit", tags=["Security & Compliance Audit Ledger"])

@router.get("/events", summary="Query append-only security and operational audit ledger")
def get_audit_events(
    limit: int = Query(50, ge=1, le=200),
    action: Optional[str] = Query(None),
    current_user: dict = Depends(require_role([UserRole.ADMINISTRATOR, UserRole.INVESTIGATOR])),
    db: Session = Depends(get_db)
):
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action == action)

    events = query.order_by(AuditLog.id.desc()).limit(limit).all()

    items = []
    for e in events:
        items.append({
            "id": e.id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "user_id": e.user_id,
            "role": e.role,
            "action": e.action,
            "resource": e.resource,
            "status": e.status,
            "details": e.details,
            "ip_address": e.ip_address
        })

    return {
        "total_returned": len(items),
        "events": items
    }
