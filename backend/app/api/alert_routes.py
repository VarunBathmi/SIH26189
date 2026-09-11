from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import UserRole
from app.security.auth import get_current_user, require_role
from app.alerts.workflow import (
    confirm_alert as confirm_alert_svc,
    dismiss_alert as dismiss_alert_svc,
    list_alerts as list_alerts_svc
)

router = APIRouter(prefix="/alerts", tags=["Human-Verified Alerts & Detection Feed"])

class AlertActionPayload(BaseModel):
    notes: Optional[str] = None

@router.get("", summary="Retrieve unified detection alerts feed (filterable by case and status)")
def get_alerts_feed(
    case_id: Optional[str] = Query(None, description="Filter by case ID"),
    status: Optional[str] = Query(None, description="Filter by status, e.g. PENDING, CONFIRMED, DISMISSED"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return list_alerts_svc(db=db, case_id=case_id, status_filter=status, page=page, page_size=page_size)

@router.post("/{alert_id}/confirm", summary="Human confirmation of an automated alert into an investigative lead")
def confirm_alert(
    alert_id: int,
    payload: AlertActionPayload,
    current_user: dict = Depends(require_role([UserRole.INVESTIGATOR, UserRole.ADMINISTRATOR])),
    db: Session = Depends(get_db)
):
    try:
        alert = confirm_alert_svc(
            db=db,
            alert_id=alert_id,
            reviewer_id=current_user.get("email"),
            reviewer_role=current_user.get("role"),
            notes=payload.notes
        )
        return {
            "message": "Alert confirmed by investigator",
            "alert_id": alert.id,
            "status": alert.status,
            "reviewed_by": alert.reviewed_by,
            "reviewed_at": alert.reviewed_at.isoformat() if alert.reviewed_at else None
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.post("/{alert_id}/dismiss", summary="Human dismissal of an alert as false positive or benign")
def dismiss_alert(
    alert_id: int,
    payload: AlertActionPayload,
    current_user: dict = Depends(require_role([UserRole.INVESTIGATOR, UserRole.ADMINISTRATOR])),
    db: Session = Depends(get_db)
):
    try:
        alert = dismiss_alert_svc(
            db=db,
            alert_id=alert_id,
            reviewer_id=current_user.get("email"),
            reviewer_role=current_user.get("role"),
            notes=payload.notes
        )
        return {
            "message": "Alert dismissed",
            "alert_id": alert.id,
            "status": alert.status,
            "reviewed_by": alert.reviewed_by,
            "reviewed_at": alert.reviewed_at.isoformat() if alert.reviewed_at else None
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
