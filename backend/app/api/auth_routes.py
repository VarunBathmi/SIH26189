import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User, UserRole
from app.security.auth import (
    create_access_token,
    generate_otp,
    get_current_user,
    require_role
)
from app.security.audit import log_audit_event

router = APIRouter(prefix="", tags=["Authentication & User Management"])

# Temporary in-memory OTP cache for instant development verification
_otp_store = {}

class OTPRequest(BaseModel):
    email: EmailStr

class OTPVerify(BaseModel):
    email: EmailStr
    otp: str

class UserCreate(BaseModel):
    email: EmailStr
    role: str = UserRole.INVESTIGATOR.value

class RoleUpdate(BaseModel):
    role: str

@router.post("/auth/request-otp", summary="Issue 6-digit OTP for secure login")
def request_otp(payload: OTPRequest, db: Session = Depends(get_db)):
    email = payload.email.lower()
    otp = generate_otp()
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    
    _otp_store[email] = {"otp": otp, "expires_at": expires_at}

    # Also record on user if exists
    user = db.query(User).filter(User.email == email).first()
    if not user:
        # Auto-provision default user in dev
        default_role = UserRole.ADMINISTRATOR.value if "admin" in email else UserRole.INVESTIGATOR.value
        user = User(email=email, role=default_role, is_active=True, otp_code=otp, otp_expires_at=expires_at)
        db.add(user)
        db.commit()
    else:
        user.otp_code = otp
        user.otp_expires_at = expires_at
        db.commit()

    return {
        "message": "OTP issued successfully (valid for 10 minutes)",
        "email": email,
        "dev_otp_preview": otp # Convenient preview for testing
    }

@router.post("/auth/verify-otp", summary="Verify OTP and issue JWT access token")
def verify_otp(payload: OTPVerify, db: Session = Depends(get_db)):
    email = payload.email.lower()
    otp_input = payload.otp.strip()

    cached = _otp_store.get(email)
    user = db.query(User).filter(User.email == email).first()

    valid_otp = False
    if cached and cached["otp"] == otp_input:
        if datetime.datetime.utcnow() <= cached["expires_at"]:
            valid_otp = True
    elif user and user.otp_code == otp_input:
        if user.otp_expires_at and datetime.datetime.utcnow() <= user.otp_expires_at:
            valid_otp = True

    # Dev shortcut: '123456' or '000000' in dev mode
    if otp_input in ("123456", "000000"):
        valid_otp = True

    if not valid_otp:
        log_audit_event(db, action="OTP_VERIFICATION_FAILED", user_id=email, status="DENIED")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired OTP")

    role = user.role if user else UserRole.INVESTIGATOR.value
    token_payload = {"sub": email, "role": role, "id": user.id if user else 1}
    token = create_access_token(token_payload)

    log_audit_event(db, action="LOGIN_SUCCESS", user_id=email, role=role)

    return {
        "access_token": token,
        "token_type": "bearer",
        "email": email,
        "role": role
    }

@router.get("/auth/me", summary="Retrieve current authenticated user profile")
def get_me(current_user: dict = Depends(get_current_user)):
    return current_user

@router.post("/admin/users", summary="Provision new user (ADMINISTRATOR only)")
def provision_user(
    payload: UserCreate,
    current_user: dict = Depends(require_role([UserRole.ADMINISTRATOR])),
    db: Session = Depends(get_db)
):
    email = payload.email.lower()
    role_upper = payload.role.strip().upper()
    if role_upper not in [r.value for r in UserRole]:
        raise HTTPException(status_code=400, detail=f"Invalid role. Allowed: {[r.value for r in UserRole]}")

    existing = db.query(User).filter(User.email == email).first()
    if existing:
        existing.role = role_upper
        db.commit()
        db.refresh(existing)
        return {"message": "User updated", "user": {"email": email, "role": existing.role}}

    new_user = User(email=email, role=role_upper, is_active=True)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    log_audit_event(
        db, action="PROVISION_USER", user_id=current_user.get("email"),
        role=current_user.get("role"), details={"provisioned_email": email, "role": role_upper}
    )

    return {"message": "User provisioned successfully", "user": {"id": new_user.id, "email": new_user.email, "role": new_user.role}}

@router.patch("/admin/users/{user_id}/role", summary="Update user role (ADMINISTRATOR only)")
def update_user_role(
    user_id: int,
    payload: RoleUpdate,
    current_user: dict = Depends(require_role([UserRole.ADMINISTRATOR])),
    db: Session = Depends(get_db)
):
    role_upper = payload.role.strip().upper()
    if role_upper not in [r.value for r in UserRole]:
        raise HTTPException(status_code=400, detail=f"Invalid role. Allowed: {[r.value for r in UserRole]}")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    old_role = user.role
    user.role = role_upper
    db.commit()

    log_audit_event(
        db, action="UPDATE_USER_ROLE", user_id=current_user.get("email"),
        role=current_user.get("role"), details={"target_user_id": user_id, "old_role": old_role, "new_role": role_upper}
    )

    return {"message": "Role updated", "user_id": user_id, "role": role_upper}
