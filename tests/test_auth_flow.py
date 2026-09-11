import pytest
from app.models import User, UserRole
from app.security.auth import create_access_token, hash_password

def test_1_signup_creates_investigator_and_issues_otp(client, db_session):
    res = client.post("/signup", json={
        "email": "investigator1@testauth.gov.in",
        "password": "SecurePassword#2026",
        "name": "Officer Sharma"
    })
    assert res.status_code in (200, 201)
    data = res.json()
    assert data["email"] == "investigator1@testauth.gov.in"
    assert data["role"] == "INVESTIGATOR"
    assert "dev_otp_preview" in data

    # Check user in DB
    user = db_session.query(User).filter(User.email == "investigator1@testauth.gov.in").first()
    assert user is not None
    assert user.role == "INVESTIGATOR"
    assert user.password_hash is not None
    assert user.password_hash != "SecurePassword#2026"

def test_2_wrong_otp_rejected(client):
    signup_res = client.post("/signup", json={
        "email": "investigator2@testauth.gov.in",
        "password": "SecurePassword#2026"
    })
    assert signup_res.status_code in (200, 201)

    verify_res = client.post("/verify-otp", json={
        "email": "investigator2@testauth.gov.in",
        "otp": "999999"
    })
    assert verify_res.status_code == 400
    assert "Invalid or expired OTP" in verify_res.json()["detail"]

def test_3_correct_otp_issues_jwt_with_role(client):
    signup_res = client.post("/signup", json={
        "email": "investigator3@testauth.gov.in",
        "password": "SecurePassword#2026"
    })
    otp = signup_res.json()["dev_otp_preview"]

    verify_res = client.post("/verify-otp", json={
        "email": "investigator3@testauth.gov.in",
        "otp": otp
    })
    assert verify_res.status_code == 200
    data = verify_res.json()
    assert "access_token" in data or "token" in data
    assert data["role"] == "INVESTIGATOR"
    assert data["user"]["is_verified"] is True

def test_4_login_mfa_flow(client):
    # 1. Signup
    client.post("/signup", json={
        "email": "investigator4@testauth.gov.in",
        "password": "SecurePassword#2026"
    })

    # 2. Login with password -> returns OTP message, not token
    login_res = client.post("/login", json={
        "email": "investigator4@testauth.gov.in",
        "password": "SecurePassword#2026"
    })
    assert login_res.status_code == 200
    data = login_res.json()
    assert "Password verified" in data["message"]
    assert "dev_otp_preview" in data

    # 3. Verify OTP -> returns JWT
    otp = data["dev_otp_preview"]
    verify_res = client.post("/verify-otp", json={
        "email": "investigator4@testauth.gov.in",
        "otp": otp
    })
    assert verify_res.status_code == 200
    assert "access_token" in verify_res.json()

def test_5_email_normalization(client):
    # Signup with MixedCase
    client.post("/signup", json={
        "email": "MixedCase.User@testauth.gov.in",
        "password": "SecurePassword#2026"
    })

    # Login with lowercase
    login_res = client.post("/login", json={
        "email": "mixedcase.user@testauth.gov.in",
        "password": "SecurePassword#2026"
    })
    assert login_res.status_code == 200
    otp = login_res.json()["dev_otp_preview"]

    # Verify with UPPERCASE
    verify_res = client.post("/verify-otp", json={
        "email": "MIXEDCASE.USER@TESTAUTH.GOV.IN",
        "otp": otp
    })
    assert verify_res.status_code == 200
    assert verify_res.json()["email"] == "mixedcase.user@testauth.gov.in"

def test_6_role_authorization(client):
    # 1. Investigator token accessing admin route -> 403
    inv_token = create_access_token({"sub": "inv@testauth.gov.in", "role": "INVESTIGATOR", "id": 10})
    inv_res = client.post("/admin/users", json={
        "email": "newbie@testauth.gov.in",
        "role": "INVESTIGATOR"
    }, headers={"Authorization": f"Bearer {inv_token}"})
    assert inv_res.status_code == 403

    # 2. Administrator token accessing admin route -> 200
    admin_token = create_access_token({"sub": "admin@testauth.gov.in", "role": "ADMINISTRATOR", "id": 1})
    admin_res = client.post("/admin/users", json={
        "email": "newbie@testauth.gov.in",
        "role": "INVESTIGATOR"
    }, headers={"Authorization": f"Bearer {admin_token}"})
    assert admin_res.status_code == 200

def test_7_account_lockout_on_failed_passwords(client):
    # Signup user
    client.post("/signup", json={
        "email": "lockout@testauth.gov.in",
        "password": "CorrectPassword#2026"
    })

    # 10 failed password attempts
    for _ in range(10):
        fail_res = client.post("/login", json={
            "email": "lockout@testauth.gov.in",
            "password": "WrongPassword!"
        })
        assert fail_res.status_code == 401

    # 11th attempt returns 423 Locked
    locked_res = client.post("/login", json={
        "email": "lockout@testauth.gov.in",
        "password": "CorrectPassword#2026"
    })
    assert locked_res.status_code == 423

def test_8_resend_otp_cooldown(client):
    client.post("/signup", json={
        "email": "resend@testauth.gov.in",
        "password": "SecurePassword#2026"
    })

    # Immediate resend after signup triggers cooldown -> 429
    resend_too_fast = client.post("/resend-otp", json={"email": "resend@testauth.gov.in"})
    assert resend_too_fast.status_code == 429
    assert "Please wait" in resend_too_fast.json()["detail"]
