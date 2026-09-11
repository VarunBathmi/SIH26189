from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import UserRole, CustodyLog
from app.security.auth import get_current_user, require_role
from app.cases.service import (
    create_case as create_case_svc,
    get_case_detail as get_case_detail_svc,
    update_case_status as update_case_status_svc,
    list_cases as list_cases_svc
)
from app.security.custody import verify_custody_chain
from app.graph.build_graph import get_case_graph

router = APIRouter(prefix="", tags=["Case Management & Custody"])

class CaseCreatePayload(BaseModel):
    case_id: str
    title: str
    description: Optional[str] = None
    case_number: Optional[str] = None

class CaseStatusPayload(BaseModel):
    status: str

@router.post("/cases", summary="Create a new criminal investigation case")
@router.post("/api/v1/cases", summary="Create a new criminal investigation case (API v1 alias)")
def create_case(
    payload: CaseCreatePayload,
    current_user: dict = Depends(require_role([UserRole.INVESTIGATOR, UserRole.ADMINISTRATOR])),
    db: Session = Depends(get_db)
):
    try:
        case = create_case_svc(
            db=db,
            case_id=payload.case_id,
            title=payload.title,
            description=payload.description,
            case_number=payload.case_number,
            created_by=current_user.get("email")
        )
        return {
            "message": "Case created successfully",
            "case_id": case.case_id,
            "title": case.title,
            "status": case.status
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/cases", summary="List cases with status filtering and pagination")
@router.get("/api/v1/cases", summary="List cases (API v1 alias)")
def get_cases(
    status: Optional[str] = Query(None, description="Comma-separated statuses, e.g. OPEN,IN_PROGRESS or COMPLETED"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return list_cases_svc(db=db, status_filter=status, page=page, page_size=page_size)

@router.get("/cases/{case_id}", summary="Retrieve detailed case profile and summary counts")
@router.get("/api/v1/cases/{case_id}", summary="Retrieve detailed case profile (API v1 alias)")
def get_case(
    case_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        return get_case_detail_svc(db=db, case_id=case_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.patch("/cases/{case_id}/status", summary="Update case status lifecycle")
def update_case_status(
    case_id: str,
    payload: CaseStatusPayload,
    current_user: dict = Depends(require_role([UserRole.INVESTIGATOR, UserRole.ADMINISTRATOR])),
    db: Session = Depends(get_db)
):
    try:
        case = update_case_status_svc(
            db=db,
            case_id=case_id,
            new_status=payload.status,
            actor_id=current_user.get("email"),
            role=current_user.get("role")
        )
        return {
            "message": "Case status updated successfully",
            "case_id": case.case_id,
            "status": case.status
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/cases/{case_id}/custody", summary="Retrieve Digital Chain of Custody records for a case")
@router.get("/api/v1/cases/{case_id}/custody", summary="Retrieve Digital Chain of Custody records (API v1 alias)")
def get_case_custody(
    case_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    records = (
        db.query(CustodyLog)
        .filter(CustodyLog.case_id == case_id)
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
            "role": r.role,
            "source_id": r.source_id,
            "timestamp": r.created_at.isoformat() if r.created_at else None
        })
    return {
        "case_id": case_id,
        "total_records": len(items),
        "custody_chain": items
    }

@router.get("/cases/{case_id}/custody/verify", summary="Verify Digital Chain of Custody hash chain integrity")
@router.get("/api/v1/cases/{case_id}/custody/verify", summary="Verify Digital Chain of Custody hash chain (API v1 alias)")
def verify_case_custody(
    case_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Chronologically verifies that every hash links to its previous hash
    and recomputes hashes from stored immutable fields to detect tampering.
    """
    return verify_custody_chain(db=db, case_id=case_id)

@router.get("/cases/{case_id}/graph", summary="Retrieve frontend-ready case network graph")
@router.get("/api/v1/cases/{case_id}/graph", summary="Retrieve frontend-ready case graph (API v1 alias)")
def get_case_graph_api(
    case_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return get_case_graph(cid=case_id)
