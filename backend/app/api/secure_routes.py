import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import UserRole, RevealRequest, RevealStatus, EntityLookup
from app.security.auth import require_role
from app.security.encryption import decrypt_name
from app.security.audit import log_audit_event
from app.security.custody import log_custody_action

router = APIRouter(prefix="/secure", tags=["Security & Dual-Authorization Identity Reveal"])

class RevealRequestPayload(BaseModel):
    hash_id: str
    case_id: str
    reason: str

class RejectPayload(BaseModel):
    reason: str

@router.post("/reveal-request", summary="Submit a dual-authorization request to unmask a pseudonymized entity")
def create_reveal_request(
    payload: RevealRequestPayload,
    current_user: dict = Depends(require_role([UserRole.INVESTIGATOR, UserRole.ADMINISTRATOR])),
    db: Session = Depends(get_db)
):
    hash_id = payload.hash_id.strip()
    reason = payload.reason.strip()
    requester_email = current_user.get("email")
    requester_role = current_user.get("role")

    if not reason or len(reason) < 5:
        raise HTTPException(status_code=400, detail="A mandatory justification reason is required for identity unmasking.")

    # Verify entity exists
    lookup = db.query(EntityLookup).filter(EntityLookup.hash_id == hash_id).first()
    if not lookup:
        raise HTTPException(status_code=404, detail="Entity with specified hash_id not found in lookup registry.")

    req = RevealRequest(
        hash_id=hash_id,
        case_id=payload.case_id,
        requested_by=requester_email,
        requester_role=requester_role,
        reason=reason,
        status=RevealStatus.PENDING.value,
        created_at=datetime.datetime.now(datetime.timezone.utc)
    )

    db.add(req)
    db.commit()
    db.refresh(req)

    log_audit_event(
        db=db,
        action="SUBMIT_REVEAL_REQUEST",
        user_id=requester_email,
        role=requester_role,
        resource=f"entity:{hash_id}",
        details={"request_id": req.id, "case_id": payload.case_id, "reason": reason}
    )

    return {
        "request_id": req.id,
        "hash_id": req.hash_id,
        "case_id": req.case_id,
        "status": req.status,
        "message": "Reveal request registered. Awaiting independent approvals from both an ADMINISTRATOR and an INVESTIGATOR."
    }

@router.post("/reveal-request/{request_id}/approve", summary="Approve reveal request (Dual-Authorization: 1 Admin + 1 distinct Investigator required)")
def approve_reveal_request(
    request_id: int,
    current_user: dict = Depends(require_role([UserRole.ADMINISTRATOR, UserRole.INVESTIGATOR])),
    db: Session = Depends(get_db)
):
    req = db.query(RevealRequest).filter(RevealRequest.id == request_id).first()
    if not req:
        raise HTTPException(status_code=404, detail=f"Reveal request #{request_id} not found.")

    if req.status != RevealStatus.PENDING.value:
        raise HTTPException(status_code=400, detail=f"Request is already resolved with status: {req.status}")

    approver_email = current_user.get("email")
    approver_role = current_user.get("role")

    # Anti-self-approval rule: Creator cannot supply approval
    if approver_email == req.requested_by:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Dual-authorization violation: Requester cannot approve their own reveal request."
        )

    now_dt = datetime.datetime.now(datetime.timezone.utc)

    # Record role approval
    if approver_role == UserRole.ADMINISTRATOR.value:
        if req.admin_approval:
            raise HTTPException(status_code=400, detail="Administrator approval has already been recorded for this request.")
        req.admin_approval = True
        req.admin_approved_by = approver_email
        req.admin_approved_at = now_dt
    elif approver_role == UserRole.INVESTIGATOR.value:
        if req.investigator_approval:
            raise HTTPException(status_code=400, detail="Investigator approval has already been recorded for this request.")
        req.investigator_approval = True
        req.investigator_approved_by = approver_email
        req.investigator_approved_at = now_dt

    # Check if dual authorization conditions are met
    if req.admin_approval and req.investigator_approval:
        req.status = RevealStatus.APPROVED.value

        # Log sensitive info reveal to custody log
        log_custody_action(
            db=db,
            case_id=req.case_id,
            action="SENSITIVE_INFORMATION_REVEALED",
            details={
                "request_id": req.id,
                "hash_id": req.hash_id,
                "reason": req.reason,
                "admin_approver": req.admin_approved_by,
                "investigator_approver": req.investigator_approved_by
            },
            user_id=approver_email,
            role=approver_role,
            source_id=f"reveal_req:{req.id}"
        )

    db.commit()
    db.refresh(req)

    log_audit_event(
        db=db,
        action="APPROVE_REVEAL_REQUEST",
        user_id=approver_email,
        role=approver_role,
        resource=f"reveal_req:{request_id}",
        details={"status": req.status, "admin_approved": req.admin_approval, "investigator_approved": req.investigator_approval}
    )

    return {
        "request_id": req.id,
        "status": req.status,
        "admin_approval": bool(req.admin_approval),
        "investigator_approval": bool(req.investigator_approval),
        "message": "Approval recorded." if req.status == RevealStatus.PENDING.value else "Dual-authorization complete! Request is APPROVED."
    }

@router.post("/reveal-request/{request_id}/reject", summary="Reject reveal request")
def reject_reveal_request(
    request_id: int,
    payload: RejectPayload,
    current_user: dict = Depends(require_role([UserRole.ADMINISTRATOR, UserRole.INVESTIGATOR])),
    db: Session = Depends(get_db)
):
    req = db.query(RevealRequest).filter(RevealRequest.id == request_id).first()
    if not req:
        raise HTTPException(status_code=404, detail=f"Reveal request #{request_id} not found.")

    if req.status != RevealStatus.PENDING.value:
        raise HTTPException(status_code=400, detail=f"Request is already resolved with status: {req.status}")

    approver_email = current_user.get("email")
    approver_role = current_user.get("role")

    req.status = RevealStatus.REJECTED.value
    req.rejection_reason = payload.reason
    db.commit()

    log_audit_event(
        db=db,
        action="REJECT_REVEAL_REQUEST",
        user_id=approver_email,
        role=approver_role,
        resource=f"reveal_req:{request_id}",
        details={"reason": payload.reason}
    )

    return {
        "request_id": req.id,
        "status": req.status,
        "rejection_reason": req.rejection_reason,
        "message": "Reveal request rejected."
    }

@router.get("/reveal-request/{request_id}", summary="Fetch reveal request status (real_name revealed ONLY if APPROVED)")
def get_reveal_request_status(
    request_id: int,
    current_user: dict = Depends(require_role([UserRole.ADMINISTRATOR, UserRole.INVESTIGATOR])),
    db: Session = Depends(get_db)
):
    req = db.query(RevealRequest).filter(RevealRequest.id == request_id).first()
    if not req:
        raise HTTPException(status_code=404, detail=f"Reveal request #{request_id} not found.")

    response = {
        "request_id": req.id,
        "hash_id": req.hash_id,
        "case_id": req.case_id,
        "requested_by": req.requested_by,
        "reason": req.reason,
        "admin_approval": bool(req.admin_approval),
        "investigator_approval": bool(req.investigator_approval),
        "status": req.status,
        "created_at": req.created_at.isoformat() if req.created_at else None
    }

    # Strict compliance rule: real_name is present ONLY when status is APPROVED
    if req.status == RevealStatus.APPROVED.value:
        lookup = db.query(EntityLookup).filter(EntityLookup.hash_id == req.hash_id).first()
        if lookup:
            decrypted = decrypt_name(lookup.encrypted_name)
            response["real_name"] = decrypted
        else:
            response["real_name"] = "Lookup record missing"

    return response
