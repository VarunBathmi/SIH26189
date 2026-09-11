import datetime
import random
import secrets
from typing import Optional, List
from fastapi import Depends, HTTPException, Header, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from app.config import settings
from app.database import get_db
from app.models import User, UserRole

security_scheme = HTTPBearer(auto_error=False)

def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None) -> str:
    """Generate a signed JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def generate_otp() -> str:
    """Generate a secure 6-digit numeric OTP."""
    return f"{secrets.randbelow(900000) + 100000}"

def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    x_role: Optional[str] = Header(None, alias="X-Role"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    db: Session = Depends(get_db)
) -> dict:
    """
    Authenticate request via JWT bearer token or development X-Role/X-User headers.
    Returns user dict: {"id": str/int, "email": str, "role": str}
    """
    # 1. Development / Testing shortcut header
    if x_role:
        role_upper = x_role.strip().upper()
        if role_upper in [r.value for r in UserRole]:
            email = x_user or f"{role_upper.lower()}@investigation.gov.in"
            return {
                "id": 1,
                "email": email,
                "role": role_upper
            }
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid X-Role: {x_role}. Allowed: {[r.value for r in UserRole]}"
        )

    # 2. JWT Bearer Token validation
    if not credentials:
        # Default fallback in development if no auth provided at all
        if settings.ENVIRONMENT == "development":
            return {
                "id": 1,
                "email": "investigator@investigation.gov.in",
                "role": UserRole.INVESTIGATOR.value
            }
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization credentials required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email: str = payload.get("sub")
        role: str = payload.get("role", UserRole.VIEWER.value)
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token claims",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return {"id": payload.get("id", 1), "email": email, "role": role}
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

def require_role(allowed_roles: List[UserRole]):
    """
    FastAPI dependency ensuring caller holds one of the specified roles.
    """
    def role_checker(current_user: dict = Depends(get_current_user)) -> dict:
        user_role = current_user.get("role")
        allowed_values = [r.value if isinstance(r, UserRole) else str(r) for r in allowed_roles]
        if user_role not in allowed_values:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation not permitted for role '{user_role}'. Required roles: {allowed_values}"
            )
        return current_user
    return role_checker
