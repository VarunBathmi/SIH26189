# Authentication & Email-OTP Multi-Factor Authentication (MFA) Specification

**Service Name:** SIH Hardened Authentication & Access Control Engine  
**Platform Alignment:** SIH26189 AI-Powered Criminal Network Analysis Platform  
**Integration Status:** Unified Reference Integration (`otp-auth-app.zip` adapted into Python FastAPI Backend & Hardened Node.js Microservice)  
**Security Standard:** Mandatory 2-Factor Authentication (Password + Email OTP), Role-Based Access Control (`ADMINISTRATOR` / `INVESTIGATOR`), PostgreSQL Persistence, SHA-256 OTP Hashes, Dual-Bucket Rate Limiting.

---

## 1. Overview

The SIH Criminal Investigation Platform uses a **unified, hardened Multi-Factor Authentication (MFA) engine** derived from the reference implementation in `otp-auth-app.zip`.

### Why It Was Integrated
1. **Mandatory MFA for Law Enforcement**: Access to sensitive First Information Reports (FIRs), Call Detail Records (CDRs), suspect identity disclosures, and financial smurfing intelligence requires proof of both knowledge (password) and possession (one-time passcode).
2. **Reference App Provenance**: The working flow from `otp-auth-app.zip` (`auth.js`, `mailer.js`, `otp.js`, `routes.js`, `store.js`) was audited, hardened against edge cases, and adapted seamlessly into both the primary Python/FastAPI backend (`backend/app/api/auth_routes.py`, `backend/app/security/auth.py`) and the standalone Node.js auth service (`auth/`).
3. **Single Source of Truth**: Both runtimes share the exact same `JWT_SECRET`, PostgreSQL database schema (`auth_users`, `auth_otps` / `users`), Bcrypt hashing, role matrix (`ADMINISTRATOR` / `INVESTIGATOR`), and stateless token claims without duplicate user tables or conflicting authorization schemes.

---

## 2. What Changed and Why

The following table documents the architectural improvements applied when adapting the reference `otp-auth-app.zip` to the production SIH platform:

| Change Category | Reference ZIP (`otp-auth-app.zip`) | Production SIH Platform (`backend/` & `auth/`) | Rationale / Benefit |
| :--- | :--- | :--- | :--- |
| **Persistence Store** | In-memory `Map` in `store.js` (lost on process restart) | PostgreSQL ACID persistence (`auth_users`, `auth_otps`) with connection pooling and memory test fallback | Server reboots and scale events do not erase registered users or active in-flight OTPs. |
| **Email Normalization** | Case-sensitive (`users.get(email)`); casing mismatches caused login failures | Normalized via `.trim().toLowerCase()` at the single store boundary | Prevents duplicate accounts and ensures `Officer.Sharma@Gov.In` and `officer.sharma@gov.in` resolve identically. |
| **JWT Role Claims** | Payload only contained `{ sub: user.id, email }` | Payload contains `{ sub: email, email, role, id, is_verified }` | Enables stateless downstream role authorization across all investigation microservices without DB round-trips. |
| **Token Expiration** | Long 7-day default (`"7d"`) | Shortened to 1 hour default (`JWT_EXPIRES_IN="1h"`) | Limits the vulnerability window of compromised bearer tokens on law enforcement forensic terminals. |
| **Role Authorization** | No role concept or role middleware | Added `requireRole("ADMINISTRATOR")` & `require_role(...)` guards | Enforces separation of duties between sworn `INVESTIGATOR` officers and `ADMINISTRATOR` supervisors. |
| **Rate Limiting** | Single endpoint limiter on `/verify-otp` (IP only) | Multi-dimensional dual-bucket rate limiters (per-IP and per-Email) on `/signup`, `/login`, `/verify-otp`, `/resend-otp` | Defends against automated credential stuffing, brute-force password spraying, and OTP exhaustion (returns `429`). |
| **Account Lockout** | No password failure tracking | Tracks failed logins; locks account for 15 minutes after 10 consecutive wrong password attempts (`HTTP 423`) | Neutralizes automated dictionary attacks on officer passwords. |
| **Async Mailer Errors** | Unhandled Promise rejections crashed on SMTP socket errors | Wrapped with `asyncHandler`; structured `502 Bad Gateway` JSON error responses | Prevents Node/Python process termination during mail server downtime. |
| **Startup Validation** | Silent startup with missing or weak secrets | Synchronous fail-fast check: enforces `JWT_SECRET` $\ge 32$ chars and verifies complete SMTP configs | Prevents running in an insecure or partially configured production state. |
| **OTP Storage** | Stored SHA-256 code hash in memory | Stored SHA-256 hash in PostgreSQL with explicit expiry and attempts left | Database dumps or compromised logs do not reveal plaintext OTP codes. |

---

## 3. Architecture

```text
                               FRONTEND (Vite / Next.js)
                                           │
                                           ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                AUTHENTICATION LAYER                                    │
│                                                                                        │
│  ┌─────────────────────────┐  ┌──────────────────────────┐  ┌───────────────────────┐  │
│  │   Password Verification │  │ OTP Engine (SHA-256)     │  │ JWT Service (HS256)   │  │
│  │   Bcrypt (Rounds: 10)   │  │ Expiry: 10m / Max: 3 tries│  │ Expiry: 1h / RBAC Claim│  │
│  └────────────┬────────────┘  └────────────┬─────────────┘  └───────────┬───────────┘  │
│               │                            │                            │              │
│               ▼                            ▼                            ▼              │
│  ┌─────────────────────────┐  ┌──────────────────────────┐  ┌───────────────────────┐  │
│  │   Account Lockout Guard │  │ Email Service (SMTP/Dev) │  │ Role Authorization    │  │
│  │   10 fails -> 15m lock  │  │ Console Fallback in Dev  │  │ Admin vs Investigator │  │
│  └─────────────────────────┘  └──────────────────────────┘  └───────────────────────┘  │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              SIH INVESTIGATION BACKEND                                 │
│                                                                                        │
│   ├── Case Records & Dossiers (`case_routes.py`) ── [INVESTIGATOR / ADMINISTRATOR]      │
│   ├── NLP Narrative Extraction (`ingestion_routes.py`) ─ [INVESTIGATOR]                 │
│   ├── Neo4j Network Graph (`graph_routes.py`) ──────── [INVESTIGATOR / ADMINISTRATOR]  │
│   ├── Financial Smurfing Analysis (`analytics_routes.py`) ─ [INVESTIGATOR]              │
│   ├── Forensic Ingestion & Co-Location (`forensics_routes.py`) ─ [INVESTIGATOR]        │
│   ├── Digital Chain of Custody (`custody.py`) ──────── [INVESTIGATOR / ADMINISTRATOR]   │
│   ├── Dual-Auth PII Unmasking (`secure_routes.py`) ─── [ADMINISTRATOR Approval Only]   │
│   └── Immutable Audit Ledger (`audit_routes.py`) ───── [ADMINISTRATOR Only]            │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Signup Flow

```text
User Submits (email, password, name)
             ↓
Normalize Email (email.trim().toLowerCase())
             ↓
Validate Password (>= 8 characters)
             ↓
Check Existing Account in PostgreSQL
    ├── Exists? ──► Return 409 Conflict
    └── New?
          ↓
Hash Password with Bcrypt
          ↓
Insert User Record (role = 'INVESTIGATOR', is_verified = false)
          ↓
Generate Cryptographic 6-digit OTP
          ↓
Store SHA-256 OTP Hash (10 min expiry, 3 attempts left)
          ↓
Dispatch OTP via SMTP (or Console Log in Dev Mode)
          ↓
Return 201 Created { message, email, role: "INVESTIGATOR" }
```

---

## 5. Login + MFA Flow

```text
User Submits (email, password)
             ↓
Normalize Email
             ↓
Check Account Lockout Status
    ├── Locked? ──► Return 423 Locked ("Locked for X minutes")
    └── Active
          ↓
Query User Record & Verify Bcrypt Password
    ├── Invalid? ──► Increment failed_login_attempts
    │                └── Reached 10? ──► Lock for 15m (Return 423)
    │                └── Under 10? ──► Return 401 Unauthorized
    └── Valid
          ↓
Reset failed_login_attempts to 0
          ↓
Generate Fresh 6-digit OTP
          ↓
Store SHA-256 OTP Hash (Invalidates any previous OTP)
          ↓
Dispatch OTP via SMTP (or Console Log in Dev Mode)
          ↓
Return 200 OK { message: "Password verified. OTP sent.", email }
(NOTE: No JWT is issued yet. Second factor is strictly required.)
```

---

## 6. OTP Verification Flow

```text
User Submits (email, otp_code)
             ↓
Normalize Email & Fetch OTP Record
    ├── Missing? ──► Return 400 ("No active OTP found")
    ├── Expired? ──► Clear OTP, Return 400 ("OTP has expired")
    └── Valid
          ↓
Compare SHA-256(submitted_code) with stored otp_hash
    ├── Mismatch?
    │       ↓
    │   Decrement attempts_left
    │       ├── 0 attempts left? ──► Clear OTP, Return 400 ("0 attempts left")
    │       └── N attempts left? ──► Return 400 ("N attempts remaining")
    └── Match!
          ↓
Clear OTP Record
          ↓
Mark User is_verified = true
          ↓
Sign JWT Token with User Payload (sub, email, role, id) [1h Lifetime]
          ↓
Return 200 OK { token, token_type: "Bearer", expires_in: "1h", user: { id, email, role } }
```

---

## 7. JWT Flow

- **Creation**: Signed using `jsonwebtoken` (Node) / `python-jose` (Python) with `HS256`.
- **Payload Claims**:
  ```json
  {
    "sub": "officer.sharma@investigation.gov.in",
    "email": "officer.sharma@investigation.gov.in",
    "role": "INVESTIGATOR",
    "id": 1,
    "is_verified": true,
    "iat": 1726059600,
    "exp": 1726063200
  }
  ```
- **Expiration**: Standard 1 hour (`JWT_EXPIRES_IN="1h"`, `ACCESS_TOKEN_EXPIRE_MINUTES=60`).
- **Verification**: Verified statelessly on every HTTP request by matching the signature against `JWT_SECRET` and asserting `exp > utcnow()`.

---

## 8. Role Model

| Role | Permitted Actions | Excluded Actions | Token Claim |
| :--- | :--- | :--- | :--- |
| `ADMINISTRATOR` | Full access: User provisioning, role promotion, audit ledger inspection, system integrity sealing, case deletion, dual-auth unmask approvals. | None | `"role": "ADMINISTRATOR"` |
| `INVESTIGATOR` | Case management, FIR narrative ingestion, NLP entity extraction, graph traversal, community detection, financial smurfing analysis, alert triage, unmask request initiation. | User administration, case deletion, self-approving unmask requests. | `"role": "INVESTIGATOR"` |
| `VIEWER` | Read-only inspection of finalized reports and sanitized alerts. | Ingestion, analysis execution, unmasking, editing. | `"role": "VIEWER"` |

---

## 9. Route Permission Mapping

| Endpoint | Method | Authentication Required | Required Role | Description |
| :--- | :--- | :--- | :--- | :--- |
| `/signup`, `/auth/signup` | `POST` | No (Public) | None (Default `INVESTIGATOR`) | Investigator self-registration |
| `/login`, `/auth/login` | `POST` | No (Public) | None | First-factor password check $\rightarrow$ dispatches OTP |
| `/verify-otp`, `/auth/verify-otp` | `POST` | No (Public) | None | Second-factor OTP verification $\rightarrow$ issues JWT |
| `/resend-otp`, `/auth/resend-otp` | `POST` | No (Public) | None | Re-dispatches OTP (with 30s cooldown) |
| `/me`, `/auth/me` | `GET` | Yes | `INVESTIGATOR`, `ADMINISTRATOR` | Current user profile |
| `/admin/users` | `POST` | Yes | `ADMINISTRATOR` Only | Provision privileged users & roles |
| `/admin/users/{id}/role` | `PATCH` | Yes | `ADMINISTRATOR` Only | Update user role |
| `/api/cases` | `POST` | Yes | `INVESTIGATOR`, `ADMINISTRATOR` | Create new investigation case |
| `/api/cases/upload-zip` | `POST` | Yes | `INVESTIGATOR`, `ADMINISTRATOR` | Ingest forensic ZIP archive |
| `/api/cases/{id}/graph` | `GET` | Yes | `INVESTIGATOR`, `ADMINISTRATOR` | Query Neo4j / NetworkX graph |
| `/api/cases/{id}` | `DELETE` | Yes | `ADMINISTRATOR` Only | Permanent case deletion |
| `/api/alerts/{id}/verify` | `POST` | Yes | `INVESTIGATOR`, `ADMINISTRATOR` | Confirm/dismiss alert |
| `/api/secure/request-reveal`| `POST` | Yes | `INVESTIGATOR`, `ADMINISTRATOR` | Request suspect identity unmasking |
| `/api/secure/approve-reveal/{id}`| `POST`| Yes | `ADMINISTRATOR` Only | Supervisor approval for unmasking |
| `/api/audit/logs` | `GET` | Yes | `ADMINISTRATOR` Only | Inspect immutable audit trail |

---

## 10. Environment Variables

| Variable Name | Required? | Purpose | Safe Default | Production Notes |
| :--- | :--- | :--- | :--- | :--- |
| `JWT_SECRET` | **Yes** | HMAC-SHA256 secret for JWT signing & verification | `dev_secret_key_change_in_production...` | Must be a cryptographically random string $\ge 32$ characters. |
| `JWT_EXPIRES_IN` | No | Token lifetime string format | `"1h"` | Investigation standard: maximum 12 hours. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | No | Python backend equivalent token lifetime | `60` | Kept in sync with `JWT_EXPIRES_IN`. |
| `DATABASE_URL` | **Yes** | PostgreSQL connection URL | `postgresql://sih_user:sih_pass@localhost:5432/crime_network_db` | Points to PostgreSQL container or cluster. |
| `DATABASE_URL_AUTH` | No | Dedicated PostgreSQL override for Node auth service | Uses `DATABASE_URL` | Useful in custom multi-DB configurations. |
| `AUTH_PORT` / `PORT` | No | Port for Node.js Auth Microservice | `5001` | Exposed on host. |
| `SMTP_HOST` | No (Dev) / **Yes** (Prod) | Hostname of SMTP mail server | Blank (Triggers dev console fallback) | e.g. `smtp.gmail.com`, `smtp.sendgrid.net`. |
| `SMTP_PORT` | No | SMTP port | `587` | `587` (STARTTLS) or `465` (SSL). |
| `SMTP_USER` | No (Dev) / **Yes** (Prod) | SMTP username or API account | Blank | In Gmail, use 16-character App Password. |
| `SMTP_PASS` | No (Dev) / **Yes** (Prod) | SMTP password or API token | Blank | Never commit to source control. |
| `SMTP_FROM` | No | Email sender header | `SIH Portal <no-reply@investigation.gov.in>` | Valid email domain format. |
| `OTP_LENGTH` | No | Number of digits in generated OTP | `6` | 6 digits standard. |
| `OTP_EXPIRY_MINUTES` | No | OTP lifetime in minutes | `10` | 5 to 15 minutes recommended. |
| `OTP_MAX_ATTEMPTS` | No | Maximum wrong attempts before OTP is invalidated | `3` | Locks OTP after 3 failed attempts. |
| `OTP_RESEND_COOLDOWN_SECONDS`| No | Minimum delay between OTP resends | `30` | Prevents email spamming. |
| `BCRYPT_SALT_ROUNDS` | No | Cost factor for password hashing | `10` | Standard secure setting. |

---

## 11. Local Development Setup

```bash
# 1. Clone workspace and navigate to root
cd SIH26189

# 2. Configure environment (.env)
cp .env.example .env

# 3. Start PostgreSQL and Neo4j containers
docker compose up -d postgres neo4j

# 4. Run Python FastAPI Backend
pip install -r requirements.txt
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload

# 5. Run Node.js Auth Microservice (Optional standalone)
cd auth
npm install
npm start
```

*In local development, `SMTP_*` variables are omitted. All issued OTPs are printed directly to the terminal console (`[DEV MAIL] Verification code for ...: 123456`) and returned in `dev_otp_preview` for rapid testing.*

---

## 12. Production Setup

In production, populate `.env` with a strong 64-character hex secret, live PostgreSQL credentials, and verified SMTP settings:

```env
NODE_ENV=production
ENVIRONMENT=production
JWT_SECRET=a8f9c2d1e4b7a0f6e3c5d8b2a1e4f7c9b0e3a6d9c2f5b8e1a4d7c0f3e6b9a2d5
JWT_EXPIRES_IN=1h
ACCESS_TOKEN_EXPIRE_MINUTES=60
DATABASE_URL=postgresql://sih_user:ProductionStrongPassword!2026@postgres:5432/crime_network_db
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASS=SG.production_api_key_goes_here
SMTP_FROM=SIH Crime Network <no-reply@investigation.gov.in>
OTP_LENGTH=6
OTP_EXPIRY_MINUTES=10
OTP_MAX_ATTEMPTS=3
OTP_RESEND_COOLDOWN_SECONDS=60
```

---

## 13. API Reference

### 13.1 `POST /signup` (or `/auth/signup`)
- **Auth Required:** No
- **Request Body:**
  ```json
  {
    "email": "officer.sharma@investigation.gov.in",
    "password": "SecurePassword#2026",
    "name": "Officer Sharma"
  }
  ```
- **Success (`201 Created` / `200 OK`):**
  ```json
  {
    "message": "Account created. Check your email for a verification code.",
    "email": "officer.sharma@investigation.gov.in",
    "role": "INVESTIGATOR",
    "dev_otp_preview": "854230"
  }
  ```

### 13.2 `POST /login` (or `/auth/login`)
- **Auth Required:** No
- **Request Body:**
  ```json
  {
    "email": "officer.sharma@investigation.gov.in",
    "password": "SecurePassword#2026"
  }
  ```
- **Success (`200 OK`):**
  ```json
  {
    "message": "Password verified. Enter the code sent to your email.",
    "email": "officer.sharma@investigation.gov.in",
    "dev_otp_preview": "854230"
  }
  ```

### 13.3 `POST /verify-otp` (or `/auth/verify-otp`)
- **Auth Required:** No
- **Request Body:**
  ```json
  {
    "email": "officer.sharma@investigation.gov.in",
    "otp": "854230"
  }
  ```
- **Success (`200 OK`):**
  ```json
  {
    "message": "Authentication successful.",
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer",
    "email": "officer.sharma@investigation.gov.in",
    "role": "INVESTIGATOR",
    "user": {
      "id": 1,
      "email": "officer.sharma@investigation.gov.in",
      "role": "INVESTIGATOR",
      "is_verified": true
    }
  }
  ```

### 13.4 `POST /resend-otp` (or `/auth/resend-otp`)
- **Auth Required:** No
- **Request Body:**
  ```json
  {
    "email": "officer.sharma@investigation.gov.in"
  }
  ```
- **Success (`200 OK`):**
  ```json
  {
    "message": "A new code has been sent.",
    "email": "officer.sharma@investigation.gov.in",
    "dev_otp_preview": "146081"
  }
  ```

### 13.5 `GET /me` (or `/auth/me`)
- **Auth Required:** Yes (`Authorization: Bearer <token>`)
- **Success (`200 OK`):**
  ```json
  {
    "user": {
      "sub": "officer.sharma@investigation.gov.in",
      "email": "officer.sharma@investigation.gov.in",
      "role": "INVESTIGATOR",
      "id": 1
    }
  }
  ```

---

## 14. Documented Error Codes

| Status Code | Meaning | Example Trigger |
| :--- | :--- | :--- |
| `400 Bad Request` | Missing field, password < 8 chars, invalid OTP format, wrong OTP code | Submitting wrong 6-digit code returns remaining attempts |
| `401 Unauthorized` | Invalid password or missing/invalid JWT token | Wrong password on login or expired bearer token on `/me` |
| `403 Forbidden` | Insufficient permissions | `INVESTIGATOR` calling `/admin/users` or `DELETE /api/cases/{id}` |
| `404 Not Found` | Target record does not exist | User not found on `/resend-otp` |
| `409 Conflict` | Resource already exists | Duplicate email registration on `/signup` |
| `423 Locked` | Account locked | 10 consecutive failed password attempts |
| `429 Too Many Requests`| Rate limit exceeded | Calling `/resend-otp` within 30s cooldown or exceeding IP burst quotas |
| `500 Internal Error` | Unhandled server fault | Database connection dropout |
| `502 Bad Gateway` | Mail transport failure | SMTP host timeout or bad mail credentials |

---

## 15. MANUAL SETUP AND TESTING STEPS

The following step-by-step instructions guide you through manual credential configuration, startup, and testing.

---

### STEP 1: Generate & Configure JWT Secret
- **What to do:** Create a high-entropy 64-character random string for signing JWT tokens.
- **Exact File:** `.env` in project root (`d:\SIH26189\.env`).
- **What value to add:** Set `JWT_SECRET=<your_64_char_random_hex>`.
- **Command to generate (PowerShell):**
  ```powershell
  -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 64 | ForEach-Object {[char]$_})
  ```
- **Expected Result:** `JWT_SECRET` in `.env` is at least 32 characters long.
- **How to verify:** Start backend; service starts without `FATAL: JWT_SECRET too short` errors.
- **What to do if it fails:** Ensure there are no spaces or quotes around the key in `.env`.

---

### STEP 2: Configure PostgreSQL Database
- **What to do:** Verify database connection string.
- **Exact File:** `.env`
- **What value to add:** `DATABASE_URL=postgresql://sih_user:sih_pass@localhost:5432/crime_network_db`
- **Command to verify:**
  ```powershell
  docker compose up -d postgres
  ```
- **Expected Result:** PostgreSQL container `sih_postgres` is running and healthy.

---

### STEP 3: Local Development (Console Log OTP Fallback)
- **What to do:** Leave `SMTP_HOST`, `SMTP_USER`, `SMTP_PASS` empty in `.env`.
- **Expected Result:** When requesting an OTP, the system prints the 6-digit code in the terminal stdout:
  ```text
  [DEV MAIL] Verification code for officer@gov.in: 625303
  ```
- **How to verify:** Inspect terminal output during `/signup` or `/login`.

---

### STEP 4: Production SMTP Configuration (Optional)
- **What to do:** If using real email delivery, provide all 5 SMTP settings in `.env`.
- **Exact File:** `.env`
- **What value to add:**
  ```env
  SMTP_HOST=smtp.gmail.com
  SMTP_PORT=587
  SMTP_USER=your_email@gmail.com
  SMTP_PASS=your_16_char_app_password
  SMTP_FROM=SIH Portal <your_email@gmail.com>
  ```
- **Expected Result:** Real emails arrive in the user's inbox containing the 6-digit verification code.

---

### STEP 5: Start the Backend
- **Command to run:**
  ```powershell
  uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
  ```
- **Expected Result:** Terminal displays `Application startup complete` on port 8000.

---

### STEP 6: Test Signup Flow via curl
- **Command to run (PowerShell):**
  ```powershell
  Invoke-RestMethod -Uri "http://localhost:8000/signup" -Method Post -ContentType "application/json" -Body '{"email":"officer.verma@investigation.gov.in","password":"SecurePassword#2026","name":"Officer Verma"}'
  ```
- **Expected Result:**
  ```json
  {
    "message": "Account created. Check your email for a verification code.",
    "email": "officer.verma@investigation.gov.in",
    "role": "INVESTIGATOR",
    "dev_otp_preview": "123456"
  }
  ```

---

### STEP 7: Test OTP Verification & JWT Retrieval
- **Command to run (PowerShell):**
  ```powershell
  Invoke-RestMethod -Uri "http://localhost:8000/verify-otp" -Method Post -ContentType "application/json" -Body '{"email":"officer.verma@investigation.gov.in","otp":"123456"}'
  ```
- **Expected Result:** Returns JWT access token:
  ```json
  {
    "message": "Authentication successful.",
    "access_token": "eyJhbGciOi...",
    "role": "INVESTIGATOR"
  }
  ```

---

### STEP 8: Test Authenticated Route with Bearer Token
- **Command to run (PowerShell):**
  ```powershell
  $token = "<paste_token_here>"
  Invoke-RestMethod -Uri "http://localhost:8000/me" -Method Get -Headers @{ Authorization = "Bearer $token" }
  ```
- **Expected Result:** Returns user profile `{ "user": { "email": "officer.verma@investigation.gov.in", "role": "INVESTIGATOR" } }`.

---

### STEP 9: Test Role Authorization (403 Forbidden on Admin Route)
- **Command to run (PowerShell):**
  ```powershell
  Invoke-RestMethod -Uri "http://localhost:8000/admin/users" -Method Post -ContentType "application/json" -Headers @{ Authorization = "Bearer $token" } -Body '{"email":"newbie@gov.in","role":"INVESTIGATOR"}'
  ```
- **Expected Result:** Returns HTTP `403 Forbidden` (`Operation not permitted for role 'INVESTIGATOR'`).

---

## 16. Automated Tests

Run the complete test suites across both runtimes:

```bash
# 1. Python Backend Automated Test Suite (51 tests: Auth, NLP, Neo4j, Forensics, Custody)
pytest -v

# 2. Node.js MFA Microservice Test Suite (10 tests: OTP, JWT, Lockout, Rate Limiting)
cd auth && npm test
```

### Expected Results:
- `pytest`: **51 passed, 0 failed** in ~67s.
- `npm test`: **10 passed, 0 failed** in ~3.4s.

---

## 17. ZIP Auth Comparison Summary

| Feature / Component | Reference ZIP (`otp-auth-app.zip`) | Existing SIH Backend | Final Unified Decision |
| :--- | :--- | :--- | :--- |
| **Language & Framework** | Node.js / Express | Python 3.12 / FastAPI | Dual-Stack Compatibility: Native FastAPI routes + standalone Express microservice |
| **Password Hashing** | `bcryptjs` (salt: 10) | `passlib` / `hashlib` | Direct standard `bcrypt` (10 rounds) in both runtimes |
| **User Persistence** | In-Memory `Map` in `store.js` | PostgreSQL `users` table | PostgreSQL tables `auth_users` & `users` with identical schemas |
| **OTP Storage** | In-Memory `Map` in `store.js` | In-Memory temporary dict | PostgreSQL `auth_otps` & SQLAlchemy models with SHA-256 code hashing |
| **Token Claims** | `{ sub: user.id, email }` | `{ sub: email, role }` | Unified: `{ sub: email, email, role, id, is_verified }` |
| **Token Expiry** | 7 Days (`"7d"`) | 12 Hours | Hardened to 1 Hour default (`"1h"`) |
| **Role Authorization** | None | `UserRole.INVESTIGATOR`, `ADMINISTRATOR` | Strict RBAC enforced on all case, graph, reveal, and audit routes |
| **Rate Limiting** | Single `/verify-otp` limiter | None on auth | Dual-bucket (IP + Email) on `/signup`, `/login`, `/verify-otp`, `/resend-otp` |
| **Account Lockout** | None | None | 15-minute lock on 10 consecutive failed password attempts |

---

## 18. Known Limitations

1. **No Refresh Token Rotation:** Tokens expire after 1 hour. Frontend clients must handle `401 TokenExpiredError` by prompting the user to re-authenticate.
2. **No Self-Service Password Reset:** Password reset links via email are not yet implemented. Password changes require database intervention or administrative provisioning (`POST /admin/users`).
3. **Single MFA Channel (Email Only):** SMS OTP and RFC 6238 TOTP authenticator apps are planned for version 5.0.
4. **Dev OTP Previews Restricted to Development:** `dev_otp_preview` is emitted in JSON responses only when `ENVIRONMENT !== "production"` and SMTP is not configured.
