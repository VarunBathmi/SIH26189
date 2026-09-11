# FRONTEND REQUIREMENTS SPECIFICATION
## SIH26189 AI-Powered Criminal Network Analysis Platform
**Document Type:** Functional API Contract & Integration Specification (No Visual Design)  
**Target Audience:** Frontend Engineers, API Integrators, QA Automation Engineers  
**Source Baseline:** Actual FastAPI + Neo4j 5.20 + PostgreSQL + NetworkX Backend (`backend/app/`)

---

## 1. Overview

The SIH26189 Backend is a forensic intelligence and criminal network analysis platform designed to ingest multi-source investigation artifacts (Call Detail Records [CDR], chat exports, file transfers, cell-tower location pings, browser history, and unstructured First Information Report [FIR] text narratives). It performs automated Natural Language Processing (NLP) entity/event extraction, computes graph topology metrics (PageRank, Betweenness Centrality, Bridge detection, Louvain community clustering, and Adamic-Adar link prediction), records cryptographic evidence integrity (SHA-256 digital custody hash chains), and enforces Dual-Authorization (Admin + Investigator) identity unmasking workflows.

### Authentication & Access Model
- **Authentication Engine:** JSON Web Tokens (JWT) signed via HMAC-SHA256 (`HS256`) with a 6-digit One-Time Password (OTP) login flow (`/auth/request-otp` and `/auth/verify-otp`).
- **Role-Based Access Control (RBAC):** Three distinct user roles exist:
  1. `ADMINISTRATOR`: User provisioning, role assignment, audit logs, dual-authorization approval.
  2. `INVESTIGATOR`: Case creation, forensic ZIP/JSON uploads, evidence verification, alert confirmation/dismissal, reveal requests.
  3. `VIEWER`: Read-only access to case graphs, timelines, analytics, and reports.
- **Development / CLI Bypass:** In development or when tokens are omitted, the backend defaults to `investigator@investigation.gov.in` (`INVESTIGATOR` role). Alternatively, requests can supply `X-Role: INVESTIGATOR` and `X-User: user@gov.in` headers for role impersonation in test environments.
- **Case Isolation Scope:** Every graph entity and relationship is isolated strictly by `case_id` in both Neo4j and NetworkX. Cases are accessible to authenticated users holding valid credentials.

---

## 2. Global Conventions

### 2.1 Base URL & Environment Configuration
- **Client Configuration Variable:** `NEXT_PUBLIC_API_BASE_URL` (Next.js) or `VITE_API_BASE_URL` (Vite).
- **Default Local Development URL:** `http://localhost:8000` (Direct) or `http://localhost:5000` (Docker Compose Proxy).
- **All routes** are served either with `/api/...` prefix or direct root paths (both are registered as aliases in `case_routes.py`, `graph_routes.py`, `main.py`).

### 2.2 Standard Response & Error Envelope

#### Success Responses:
Standard JSON objects with typed fields or direct file streams for exports.

#### Error Responses:
The backend standardizes on FastAPI `HTTPException` envelopes:
```json
{
  "detail": "Descriptive error message explaining what failed validation or query"
}
```
*Note for Frontend:* In 422 Unprocessable Entity validation errors (e.g., missing mandatory JSON fields), FastAPI returns a structured validation error array:
```json
{
  "detail": [
    {
      "loc": ["body", "entities", 0, "entity_id"],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```
The frontend error parser must handle both `typeof error.detail === 'string'` and `Array.isArray(error.detail)`.

### 2.3 Hard Request & Data Caps (Client-Side Pre-Validation)

| Constraint | Backend Value | Source File | Frontend Rule |
|---|---|---|---|
| **Max ZIP Archive Uncompressed Size** | `200 MB` (`209,715,200 bytes`) | `forensics/zip_ingest.py:34` | Reject client-side if declared uncompressed size > 200MB. |
| **Max Files inside ZIP Archive** | `500 files` | `forensics/zip_ingest.py:35` | Reject client-side if file count > 500. |
| **Max Evidence Binary Upload Size** | `500 MB` (`524,288,000 bytes`) | `config.py:36` | File upload form limit for raw disk images/PCAPs. |
| **Max Graph Node Query Limit** | `100` | `analytics_routes.py` | Pagination default: `page_size=50`, `max=100`. |
| **Max Timeline Event Limit** | `500 events` | `neo4j_engine.py:366` | Timeline queries capped to 500 chronological events. |
| **OTP Validity Window** | `10 minutes` | `auth_routes.py:39` | Frontend countdown timer: 600 seconds. |

---

## 3. Full Endpoint Reference

### 3.1 Health & Diagnostics

#### `GET /api/health` (or `GET /health`)
- **Action:** Platform liveness & database connectivity verification.
- **Inputs:** None.
- **Success Response (200 OK):**
```json
{
  "status": "healthy",
  "database": "connected",
  "neo4j": "connected",
  "version": "4.0.0",
  "environment": "development"
}
```
- **Error Response (200 / 503):** Returns `"status": "degraded"` if database connectivity fails.
- **Usage:** Polled on application bootstrap or displayed in system health indicators.

---

### 3.2 Authentication & User Management

#### `POST /auth/request-otp`
- **Action:** Request a 6-digit login OTP for an investigator email.
- **Request Headers:** `Content-Type: application/json`
- **Request Body:**
```json
{
  "email": "inspector_sharma@investigation.gov.in"
}
```
- **Success Response (200 OK):**
```json
{
  "message": "OTP issued successfully (valid for 10 minutes)",
  "email": "inspector_sharma@investigation.gov.in",
  "dev_otp_preview": "847291"
}
```
- **Error Response:** `422 Unprocessable Entity` on invalid email syntax.

#### `POST /auth/verify-otp`
- **Action:** Verify 6-digit OTP and receive JWT access token.
- **Request Headers:** `Content-Type: application/json`
- **Request Body:**
```json
{
  "email": "inspector_sharma@investigation.gov.in",
  "otp": "847291"
}
```
- **Success Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "email": "inspector_sharma@investigation.gov.in",
  "role": "INVESTIGATOR"
}
```
- **Error Response (400 Bad Request):**
```json
{
  "detail": "Invalid or expired OTP"
}
```

#### `GET /auth/me`
- **Action:** Fetch authenticated profile of currently logged-in user.
- **Request Headers:** `Authorization: Bearer <access_token>`
- **Success Response (200 OK):**
```json
{
  "id": 1,
  "email": "inspector_sharma@investigation.gov.in",
  "role": "INVESTIGATOR"
}
```
- **Error Response (401 Unauthorized):** `{"detail": "Authorization credentials required"}`.

---

### 3.3 Case Management & Ingestion

#### `POST /api/cases/load-demo`
- **Action:** Load synthetic multi-entity investigation case (`CASE-DEMO-001`) into Neo4j and relational store.
- **Inputs:** None.
- **Success Response (200 OK):**
```json
{
  "status": "ok",
  "case_id": "CASE-DEMO-001",
  "message": "Demo case loaded successfully",
  "entity_count": 3,
  "artifact_count": 3
}
```

#### `POST /api/cases/upload-zip` (or `POST /cases/upload-zip`)
- **Action:** Multi-part forensic evidence ZIP archive upload with automated SHA-256 pre-hashing, custody logging, CSV normalization, and Neo4j graph population.
- **Request Headers:** `Content-Type: multipart/form-data`
- **Form Parameters:**
  - `file`: `UploadFile` (Binary `.zip` archive, max 200MB uncompressed).
  - `case_id`: Optional query parameter string to override generated case ID (e.g. `?case_id=CASE-2026-09A`).
- **Archive File Schema Supported:**
  - `entities.csv` (Columns: `entity_id,name,phone,device_id,ip`)
  - `calls.csv` (Columns: `caller_id,callee_id,duration_sec,timestamp`)
  - `chats.csv` (Columns: `sender_id,receiver_id,platform,timestamp,message`)
  - `locations.csv` (Columns: `entity_id,lat,lng,timestamp`)
  - `files.csv` (Columns: `owner_id,transferred_to_id,filename,hash_sha256,timestamp`)
  - `browser_history.csv` (Columns: `entity_id,url,timestamp`)
  - `fir.txt` / `fir.docx` / `fir.pdf` (Raw narrative text)
  - `case_meta.json` (Optional metadata: `{"case_id": "...", "title": "...", "note": "..."}`)
- **Success Response (200 OK):**
```json
{
  "status": "SUCCESS",
  "case_id": "CASE-7A9B3C1D",
  "parent_zip_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "entity_count": 4,
  "artifact_count": 6,
  "file_hashes": {
    "entities.csv": "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
    "calls.csv": "8f434346648f6b96df89dda901c5176b10e6d059612d556c42930a09e0a2ca39",
    "locations.csv": "9f83c605d4c82c3dd5e750def09f26455e263fe606e5392326b2b7e60e66529b"
  },
  "warnings": [],
  "has_fir_text": true,
  "engine": "Neo4j 5.20 + NetworkX Dual Engine"
}
```
- **Error Responses:**
  - `400 Bad Request`: `{"detail": "Corrupt or invalid ZIP archive. File could not be decompressed."}`
  - `400 Bad Request`: `{"detail": "Total uncompressed ZIP size exceeds 200MB limit. Ingestion halted."}`
  - `400 Bad Request`: `{"detail": "Password-protected or encrypted ZIP archive detected (calls.csv). Unencrypted archive is required."}`
  - `400 Bad Request`: `{"detail": "No forensic data files found in archive (expected calls.csv, chats.csv, files.csv, locations.csv, entities.csv, or FIR narrative)."}`

#### `POST /api/cases/upload` (or `POST /cases/upload`)
- **Action:** Direct JSON ingestion of entities and artifacts.
- **Request Body:**
```json
{
  "case_id": "CASE-MANUAL-001",
  "title": "Operation Cyber Track",
  "note": "Intelligence collected from manual field surveillance",
  "entities": [
    {"entity_id": "P1", "name": "Rahul Sharma", "phone": "9990001", "device_id": "D1", "ip": "10.0.0.1"},
    {"entity_id": "P2", "name": "Amit Kumar", "phone": "9990002", "device_id": "D2", "ip": "10.0.0.2"}
  ],
  "artifacts": [
    {"record_type": "call", "caller_id": "P1", "callee_id": "P2", "duration_sec": 120, "timestamp": "2026-03-12T21:05:00", "record_id": "CALL-01"}
  ]
}
```
- **Success Response (200 OK):**
```json
{
  "status": "ok",
  "case_id": "CASE-MANUAL-001",
  "entities_loaded": 2,
  "artifacts_loaded": 1,
  "message": "Case CASE-MANUAL-001 ingested successfully."
}
```
- **Error Response (400 Bad Request):** `{"detail": "Invalid payload: at least one entity or artifact is required."}`

#### `GET /api/cases` (or `GET /cases`)
- **Action:** List cases with optional status filtering and pagination.
- **Query Parameters:**
  - `status` (string, optional): `OPEN`, `IN_PROGRESS`, `COMPLETED`, `CLOSED`
  - `page` (integer, default `1`, min `1`)
  - `page_size` (integer, default `50`, min `1`, max `100`)
- **Success Response (200 OK):**
```json
{
  "total_cases": 12,
  "page": 1,
  "page_size": 50,
  "cases": [
    {
      "case_id": "CASE-DEMO-001",
      "case_number": "CASE-DEMO-001",
      "title": "Operation Cyber Track Demo",
      "description": "Demo investigation case with synthetic forensic CDR & entity data",
      "status": "OPEN",
      "created_by": "investigator@investigation.gov.in",
      "created_at": "2026-09-11T11:00:00Z",
      "updated_at": "2026-09-11T11:00:00Z"
    }
  ]
}
```

#### `GET /api/cases/{case_id}` (or `GET /cases/{case_id}`)
- **Action:** Retrieve case profile with summary counts of evidence and records.
- **Path Parameter:** `case_id` (string)
- **Success Response (200 OK):**
```json
{
  "case_id": "CASE-DEMO-001",
  "case_number": "CASE-DEMO-001",
  "title": "Operation Cyber Track Demo",
  "description": "Demo investigation case with synthetic forensic CDR & entity data",
  "status": "OPEN",
  "created_by": "investigator@investigation.gov.in",
  "created_at": "2026-09-11T11:00:00Z",
  "summary": {
    "documents_count": 1,
    "calls_count": 4,
    "transactions_count": 2,
    "evidence_count": 3,
    "person_matches_count": 1
  }
}
```
- **Error Response (404 Not Found):** `{"detail": "Case 'CASE-UNKNOWN' not found"}`

#### `GET /api/cases/{case_id}/custody` (or `GET /api/cases/{case_id}/log`)
- **Action:** Retrieve immutable Digital Chain of Custody event ledger for a case.
- **Success Response (200 OK):**
```json
{
  "case_id": "CASE-DEMO-001",
  "total_records": 3,
  "custody_chain": [
    {
      "id": 1,
      "case_id": "CASE-DEMO-001",
      "action": "FORENSIC_ZIP_INGESTED",
      "details": {
        "parent_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "entity_count": 3,
        "artifact_count": 4
      },
      "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "current_hash": "84d72b2c918a3a0c2e3f5d1e2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b",
      "user_id": "inspector_sharma@investigation.gov.in",
      "role": "INVESTIGATOR",
      "timestamp": "2026-09-11T11:05:00Z"
    }
  ]
}
```

#### `GET /api/cases/{case_id}/custody/verify`
- **Action:** Verifies SHA-256 hash-chain integrity to detect tampering or unauthorized modification.
- **Success Response (200 OK):**
```json
{
  "case_id": "CASE-DEMO-001",
  "chain_valid": true,
  "total_records_checked": 3,
  "verified_at": "2026-09-11T11:10:00Z",
  "status": "VERIFIED_INTEGRITY"
}
```

---

### 3.4 Network Graph & Analytical Algorithms

#### `GET /api/cases/{case_id}/graph`
- **Action:** Retrieve frontend-ready case network graph formatted for Cytoscape.js, Vis.js, or D3.js force-directed layouts.
- **Query Parameters:**
  - `source` (string, default `"neo4j"`, options: `"neo4j"`, `"networkx"`)
- **Success Response (200 OK):**
```json
{
  "case_id": "CASE-DEMO-001",
  "nodes": [
    {
      "id": "P1",
      "label": "Rahul Sharma",
      "type": "Entity",
      "properties": {
        "entity_id": "P1",
        "name": "Rahul Sharma",
        "phone": "9990001",
        "device_id": "D1",
        "ip": "10.0.0.1",
        "case_id": "CASE-DEMO-001"
      }
    },
    {
      "id": "P2",
      "label": "Amit Kumar",
      "type": "Entity",
      "properties": {
        "entity_id": "P2",
        "name": "Amit Kumar",
        "phone": "9990002",
        "device_id": "D2",
        "ip": "10.0.0.2",
        "case_id": "CASE-DEMO-001"
      }
    }
  ],
  "links": [
    {
      "source": "P1",
      "target": "P2",
      "relation": "CALLED",
      "type": "CALLED",
      "timestamp": "2026-03-12T21:05:00",
      "properties": {
        "record_id": "CALL-DEMO-01",
        "duration_sec": 120,
        "timestamp": "2026-03-12T21:05:00",
        "case_id": "CASE-DEMO-001"
      }
    }
  ],
  "edges": [ /* Mirrors links array for backwards compatibility */ ],
  "metadata": {
    "node_count": 2,
    "link_count": 1,
    "engine": "Neo4j Cypher",
    "generated_at": "2026-09-11T11:12:00Z"
  }
}
```

#### `GET /api/cases/{case_id}/centrality`
- **Action:** Compute structural importance via PageRank, Betweenness Centrality, and 7-dimension Priority Scores.
- **Success Response (200 OK):**
```json
{
  "case_id": "CASE-DEMO-001",
  "pagerank": {
    "P1": 0.4521,
    "P2": 0.5479
  },
  "betweenness": {
    "P1": 0.5,
    "P2": 0.5
  },
  "priority_scores": {
    "case_id": "CASE-DEMO-001",
    "top_influencers": [
      {
        "id": "P2",
        "label": "Amit Kumar",
        "type": "Entity",
        "priority_score": 84.5,
        "pagerank": 0.5479,
        "betweenness": 0.5,
        "degree": 3,
        "score_breakdown": {
          "connectivity_weight_20": 20.0,
          "pagerank_weight_15": 15.0,
          "bridge_weight_15": 15.0,
          "suspicious_calls_weight_15": 10.5,
          "document_mentions_weight_15": 10.0,
          "fuzzy_match_weight_10": 7.0,
          "financial_flags_weight_10": 7.0
        }
      }
    ],
    "total_ranked_entities": 2,
    "disclaimer": "This score reflects network position and pattern frequency only. It is not a prediction of criminal behavior and must not be treated as a finding — all flagged individuals require independent human investigation."
  }
}
```

#### `GET /api/cases/{case_id}/communities`
- **Action:** Retrieve Louvain community clustering identifying criminal sub-cells / conspiracy syndicates.
- **Success Response (200 OK):**
```json
{
  "case_id": "CASE-DEMO-001",
  "total_communities": 1,
  "communities": [
    {
      "community_id": 1,
      "member_count": 3,
      "members": [
        {"id": "P1", "label": "Rahul Sharma", "type": "Entity"},
        {"id": "P2", "label": "Amit Kumar", "type": "Entity"},
        {"id": "P3", "label": "Vikram Seth", "type": "Entity"}
      ]
    }
  ],
  "disclaimer": "This score reflects network position and pattern frequency only..."
}
```

#### `GET /api/cases/{case_id}/anomalies`
- **Action:** Expose structural anomalies, network cut-vertices (bridge nodes), and partition vulnerability.
- **Success Response (200 OK):**
```json
{
  "case_id": "CASE-DEMO-001",
  "high_priority_anomalies": [
    {
      "id": "P2",
      "label": "Amit Kumar",
      "priority_score": 84.5
    }
  ],
  "cut_vertices": [
    {
      "id": "P2",
      "label": "Amit Kumar",
      "type": "Entity",
      "role": "Cut-Vertex (Critical Connector)",
      "impact": "Removing this entity partitions the network into disconnected components"
    }
  ],
  "bridge_edges": [
    ["P1", "P2"]
  ]
}
```

#### `GET /api/cases/{case_id}/link-predictions`
- **Action:** Adamic-Adar topology link prediction for hidden or unobserved associations.
- **Query Parameters:**
  - `limit` (integer, default `10`, min `1`, max `50`)
- **Success Response (200 OK):**
```json
{
  "case_id": "CASE-DEMO-001",
  "predicted_links": [
    {
      "source": "P1",
      "target": "P3",
      "score": 1.4427,
      "reason": "High shared neighborhood topology"
    }
  ],
  "disclaimer": "This score reflects network position and pattern frequency only..."
}
```

#### `GET /api/cases/{case_id}/path`
- **Action:** Compute shortest connecting criminal relationship path between two selected entities.
- **Query Parameters:**
  - `source` (string, required): Starting `entity_id`
  - `target` (string, required): Destination `entity_id`
- **Success Response (200 OK):**
```json
{
  "case_id": "CASE-DEMO-001",
  "source": "P1",
  "target": "P3",
  "path_length": 2,
  "path": ["P1", "P2", "P3"],
  "exists": true
}
```
- **When no connecting path exists (200 OK):**
```json
{
  "case_id": "CASE-DEMO-001",
  "source": "P1",
  "target": "P99",
  "path_length": 0,
  "path": [],
  "exists": false
}
```

#### `GET /api/cases/{case_id}/timeline`
- **Action:** Chronological forensic event timeline across calls, messages, file transfers, and locations.
- **Query Parameters:**
  - `entity_id` (string, optional): Filter timeline events involving this specific entity
  - `limit` (integer, default `500`, min `1`, max `500`)
- **Success Response (200 OK):**
```json
[
  {
    "timestamp": "2026-03-12T21:05:00",
    "relation": "CALLED",
    "source": "P1",
    "target": "P2",
    "properties": {
      "record_id": "CALL-DEMO-01",
      "duration_sec": 120,
      "case_id": "CASE-DEMO-001"
    }
  },
  {
    "timestamp": "2026-03-12T21:15:00",
    "relation": "MESSAGED",
    "source": "P2",
    "target": "P3",
    "properties": {
      "record_id": "CHAT-DEMO-01",
      "platform": "Telegram",
      "case_id": "CASE-DEMO-001"
    }
  }
]
```

---

### 3.5 Natural Language Processing (FIR Narrative Analysis)

#### `POST /ingestion/analyze-text`
- **Action:** Interactive on-demand NLP analysis of raw text narrative (FIR, interrogations, intelligence notes).
- **Request Body:**
```json
{
  "text": "On 12-03-2026 at 21:05, Rahul Sharma called Amit Kumar (+919990002). Later Rahul transferred 5,00,000 INR to account 1234567890 at Axis Bank Jaipur Branch.",
  "case_id": "CASE-PREVIEW",
  "document_id": "DOC-001"
}
```
- **Success Response (200 OK):**
```json
{
  "status": "SUCCESS",
  "case_id": "CASE-PREVIEW",
  "document_id": "DOC-001",
  "summary": {
    "entities_detected": 6,
    "events_detected": 2,
    "relationships_detected": 2,
    "possible_person_matches": 0,
    "message": "Text processed successfully: 6 entities, 2 events, 2 relationships detected."
  },
  "entities": {
    "PERSON": ["Rahul Sharma", "Amit Kumar"],
    "PHONE": ["+919990002"],
    "MONEY": ["5,00,000 INR"],
    "BANK_ACCOUNT": ["1234567890"],
    "ORGANIZATION": ["Axis Bank"],
    "LOCATION": ["Jaipur"]
  },
  "detailed_entities": [
    {
      "entity_id": "RAHUL_SHARMA",
      "text": "Rahul Sharma",
      "label": "PERSON",
      "start_char": 24,
      "end_char": 36,
      "confidence": 0.95,
      "source_document": "DOC-001"
    }
  ],
  "events": {
    "calls": [
      {
        "caller": "Rahul Sharma",
        "callee": "Amit Kumar",
        "timestamp": "21:05",
        "raw_text": "Rahul Sharma called Amit Kumar"
      }
    ],
    "transactions": [
      {
        "sender": "Rahul",
        "receiver": "account 1234567890",
        "amount": 500000.0,
        "currency": "INR",
        "bank": "Axis Bank",
        "landmark": "Jaipur Branch"
      }
    ]
  },
  "relationships": [
    {
      "source": "Rahul Sharma",
      "target": "Amit Kumar",
      "relation": "CALLED",
      "confidence": 0.95,
      "evidence_snippet": "Rahul Sharma called Amit Kumar"
    }
  ],
  "candidate_person_matches": [],
  "disclaimer": "NLP outputs are investigative leads for human review, not verified judicial facts."
}
```

---

### 3.6 Human-in-the-Loop Alerts & Verification

#### `GET /alerts`
- **Action:** Retrieve detection feed of automated alerts requiring investigator review.
- **Query Parameters:**
  - `case_id` (string, optional)
  - `status` (string, optional: `PENDING`, `CONFIRMED`, `DISMISSED`)
  - `page` (integer, default `1`)
  - `page_size` (integer, default `50`)
- **Success Response (200 OK):**
```json
{
  "total_alerts": 2,
  "page": 1,
  "page_size": 50,
  "alerts": [
    {
      "id": 101,
      "case_id": "CASE-DEMO-001",
      "alert_type": "CALL_BURST",
      "related_entities": ["P1", "P2"],
      "source_module": "NLP_CALL_DETECTION",
      "reason": "14 short calls detected within 30 minutes between P1 and P2",
      "detected_at": "2026-09-11T11:05:00Z",
      "status": "PENDING",
      "reviewed_by": null,
      "reviewed_at": null,
      "review_notes": null
    }
  ]
}
```

#### `POST /alerts/{alert_id}/confirm`
- **Action:** Confirm an automated alert into an active judicial investigative lead.
- **Request Body:**
```json
{
  "notes": "Verified against seized device call log CDR table."
}
```
- **Success Response (200 OK):**
```json
{
  "message": "Alert confirmed by investigator",
  "alert_id": 101,
  "status": "CONFIRMED",
  "reviewed_by": "inspector_sharma@investigation.gov.in",
  "reviewed_at": "2026-09-11T11:20:00Z"
}
```

#### `POST /alerts/{alert_id}/dismiss`
- **Action:** Dismiss false positive or benign alert.
- **Request Body:**
```json
{
  "notes": "Legitimate business communications during business hours."
}
```
- **Success Response (200 OK):**
```json
{
  "message": "Alert dismissed",
  "alert_id": 101,
  "status": "DISMISSED",
  "reviewed_by": "inspector_sharma@investigation.gov.in",
  "reviewed_at": "2026-09-11T11:20:00Z"
}
```

---

### 3.7 Dual-Authorization Identity Unmasking (PII Protection)

*Privacy Rule:* In public/standard views, suspect names are pseudonymized with SHA-256 `hash_id`s. Real identities are encrypted using AES-128-CBC + HMAC-SHA256 (Fernet) in `entity_lookup`. Revealing a real name requires approvals from both an `ADMINISTRATOR` and a distinct `INVESTIGATOR`.

#### `POST /secure/reveal-request`
- **Action:** Submit formal request to unmask a pseudonymized suspect.
- **Request Body:**
```json
{
  "hash_id": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "case_id": "CASE-DEMO-001",
  "reason": "Warrant #WR-2026-88 issued by Chief Judicial Magistrate for suspect arrest."
}
```
- **Success Response (200 OK):**
```json
{
  "request_id": 12,
  "hash_id": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "case_id": "CASE-DEMO-001",
  "status": "PENDING",
  "message": "Reveal request registered. Awaiting independent approvals from both an ADMINISTRATOR and an INVESTIGATOR."
}
```

#### `POST /secure/reveal-request/{request_id}/approve`
- **Action:** Record role approval (requires 1 Admin + 1 distinct Investigator; anti-self-approval enforced).
- **Inputs:** Path `request_id` (integer).
- **Success Response (200 OK):**
```json
{
  "request_id": 12,
  "status": "APPROVED",
  "admin_approval": true,
  "investigator_approval": true,
  "message": "Approval recorded successfully. Dual-authorization criteria satisfied."
}
```

#### `GET /secure/reveal/{hash_id}`
- **Action:** Fetch unmasked decrypted name once request reaches `APPROVED` status.
- **Success Response (200 OK):**
```json
{
  "hash_id": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "real_name": "Vikram Malhotra",
  "entity_type": "Person",
  "unmasked_by": "inspector_sharma@investigation.gov.in",
  "unmasked_at": "2026-09-11T11:30:00Z"
}
```
- **Error Response (403 Forbidden):** `{"detail": "Dual authorization required: 1 Admin and 1 Investigator approval needed before unmasking."}`

---

### 3.8 Export Endpoints (File Downloads)

All export endpoints return binary file streams with standard HTTP headers (`Content-Disposition: attachment; filename=...`).

| Method & Endpoint | Content-Type | Download File Name | Description |
|---|---|---|---|
| `GET /api/cases/{case_id}/export/report.pdf` | `application/pdf` | `Case_Dossier_{case_id}.pdf` | Official Multi-page PDF Case Dossier with Evidence Integrity Matrix & Top Influencers. |
| `GET /api/cases/{case_id}/export/entities.csv` | `text/csv` | `entities_{case_id}.csv` | Raw CSV table of all unique entity nodes (`entity_id, label, type, name, phone, device_id, ip`). |
| `GET /api/cases/{case_id}/export/artifacts.csv` | `text/csv` | `artifacts_{case_id}.csv` | Raw CSV table of all forensic relationships (`source, target, relation, type, timestamp, record_id`). |
| `GET /api/cases/{case_id}/export/analysis.csv` | `text/csv` | `analysis_{case_id}.csv` | Calculated graph metrics CSV (`entity_id, pagerank, betweenness_centrality, priority_score`). |

---

## 4. Data Model Reference

### 4.1 `Entity` Model

```typescript
interface Entity {
  entity_id: string;      // Required, unique identifier within case (e.g. "P1", "SUSPECT-01")
  name: string;           // Person or Organization full name
  phone?: string;         // E.164 phone string (e.g. "+919990001")
  device_id?: string;     // IMEI / Hardware MAC ID (e.g. "DEV-991")
  ip?: string;            // Valid IPv4/IPv6 address (e.g. "192.168.1.50")
  case_id?: string;       // Bound case identifier
}
```

### 4.2 Forensic Artifact Sub-Types

When constructing forms or rendering artifact tables, branch on `record_type`:

```typescript
type ForensicArtifact =
  | CallArtifact
  | ChatArtifact
  | FileArtifact
  | LocationArtifact
  | BrowserArtifact;

interface BaseArtifact {
  record_id?: string;     // Forensic evidence reference ID
  timestamp: string;      // ISO-8601 string: YYYY-MM-DDTHH:MM:SS
}

interface CallArtifact extends BaseArtifact {
  record_type: "call";
  caller_id: string;      // Source entity_id
  callee_id: string;      // Target entity_id
  duration_sec: number;   // Call duration in seconds (integer)
}

interface ChatArtifact extends BaseArtifact {
  record_type: "chat";
  sender_id: string;      // Source entity_id
  receiver_id: string;    // Target entity_id
  platform: string;       // "Signal" | "WhatsApp" | "Telegram" | "SMS"
  message?: string;       // Intercepted text message
}

interface FileArtifact extends BaseArtifact {
  record_type: "file_artifact" | "file";
  owner_id: string;       // Sender / Uploader entity_id
  transferred_to_id: string; // Recipient entity_id
  filename: string;       // e.g. "ledger.xlsx"
  hash_sha256: string;    // Hexadecimal SHA-256 hash (64 chars)
}

interface LocationArtifact extends BaseArtifact {
  record_type: "location" | "location_ping" | "co_located";
  entity_id?: string;     // Ping subject
  lat: number;            // Latitude (-90.0 to 90.0)
  lng: number;            // Longitude (-180.0 to 180.0)
  location_name?: string; // Optional landmark string
  // For pre-computed co-location:
  entity1?: string;
  entity2?: string;
  distance_km?: number;   // Distance separation in km
}

interface BrowserArtifact extends BaseArtifact {
  record_type: "browser_history";
  entity_id: string;      // Device owner entity_id
  url: string;            // Visited URL
  title?: string;         // Webpage title
}
```

---

## 5. Screen/Flow → Endpoint Mapping

### Flow 1: Investigator Loads Demo Exploration Case
1. **User Action:** Clicks "Load Demo Dataset" button on Welcome / Empty state screen.
2. **API Call:** `POST /api/cases/load-demo`
3. **Behavior:** Backend loads 3 entities and 3 relationships into Neo4j + SQLite.
4. **Transition:** Redirect to `/cases/CASE-DEMO-001/graph`.

### Flow 2: Investigator Ingests Forensic ZIP Evidence
1. **User Action:** Drags and drops a `.zip` archive into the "Forensic Ingestion" dropzone.
2. **Pre-check:** Ensure file extension is `.zip` and file size < 200MB.
3. **API Call:** `POST /api/cases/upload-zip` (`Content-Type: multipart/form-data`, form field `file`).
4. **On 200 Success:**
   - Display success modal showing: `case_id`, `entity_count`, `artifact_count`, and parent SHA-256.
   - If `warnings` array is non-empty, display warning banner with skipped rows or malformed entries.
   - Redirect to `/cases/{case_id}/graph`.
5. **On 400 Error:** Show `error.detail` directly in error alert (messages are user-friendly: e.g. "Password-protected or encrypted ZIP archive detected").

### Flow 3: Case Dashboard & Audit Custody Verification
1. **User Action:** Navigates to Case Profile or Custody Ledger tab.
2. **API Calls:**
   - `GET /api/cases/{case_id}` (Case metadata & entity/call counters)
   - `GET /api/cases/{case_id}/custody` (Full digital chain of custody history)
   - `GET /api/cases/{case_id}/custody/verify` (Hash-chain verification badge)
3. **Behavior:** Display a green "Tamper-Proof Hash Chain Verified" badge if `chain_valid === true`.

### Flow 4: Interactive Graph Exploration & Layout Visualization
1. **User Action:** Opens Network Graph screen for active case.
2. **API Call:** `GET /api/cases/{case_id}/graph?source=neo4j`
3. **Behavior:** Feed `nodes` and `links` to Cytoscape.js / D3 force simulation.
4. **Interactive Controls:**
   - Clicking a node highlights its direct 1-hop neighborhood.
   - Node badge displays `type` (Person, Device, Organization, Phone).
   - Edge labels display forensic relation (`CALLED`, `MESSAGED`, `TRANSFERRED_FILE`, `CO_LOCATED`).

### Flow 5: Algorithmic Analytics Dashboard (Centrality, Communities, Anomalies)
1. **User Action:** Clicks "Network Analytics" tab.
2. **API Calls (Trigger in parallel):**
   - `GET /api/cases/{case_id}/centrality`
   - `GET /api/cases/{case_id}/communities`
   - `GET /api/cases/{case_id}/anomalies`
   - `GET /api/cases/{case_id}/link-predictions`
3. **Behavior:**
   - Top Influencers Table: Renders ranked suspects with 7-dimension score breakdown bar.
   - Community Clusters View: Groups nodes by `community_id` with color-coded boundaries.
   - Cut-Vertex Warning Banner: Highlights critical broker entities whose removal partitions the criminal network.
   - Mandatory Disclaimer: Display backend disclaimer string at bottom of analytics view.

### Flow 6: Shortest Path Lookup Between Suspects
1. **User Action:** Selects Source Suspect and Target Suspect from dropdown select menus.
2. **Input Requirement:** Frontend **MUST populate dropdowns from known `entity_id`s** in the graph (retrieved via `/graph`). Do NOT use free-text inputs.
3. **API Call:** `GET /api/cases/{case_id}/path?source={source_id}&target={target_id}`
4. **Behavior:** Highlight connecting path nodes and edges in graph canvas. If `exists === false`, show "No connecting relationship path discovered."

### Flow 7: Forensic Event Timeline Filtering
1. **User Action:** Opens Timeline tab.
2. **API Call:** `GET /api/cases/{case_id}/timeline?limit=200`
3. **Optional Filter:** Selecting a specific entity triggers `GET /api/cases/{case_id}/timeline?entity_id={entity_id}`.
4. **Behavior:** Render chronological card stream with timestamp, source, target, and artifact type badges.

### Flow 8: Unstructured Text / FIR Interactive NLP Analysis
1. **User Action:** Pastes FIR narrative text or interrogation transcript into the NLP Intelligence Lab textarea.
2. **API Call:** `POST /ingestion/analyze-text` with `{ text: "...", case_id: "..." }`.
3. **Behavior:** Instantly highlights extracted entities in text with color-coded chips (PERSON, PHONE, BANK_ACCOUNT, MONEY, LOCATION, VEHICLE), displays detected events table, and renders extracted relationship graph preview.

### Flow 9: Human Confirmation of Automated Alerts
1. **User Action:** Reviews Alerts Feed at `/alerts?case_id={case_id}&status=PENDING`.
2. **Confirm Lead:** User types verification note and clicks "Confirm" -> `POST /alerts/{alert_id}/confirm`.
3. **Dismiss Alert:** User types justification and clicks "Dismiss" -> `POST /alerts/{alert_id}/dismiss`.
4. **Behavior:** Optimistically update card badge to `CONFIRMED` or `DISMISSED`.

### Flow 10: Exporting Dossiers & CSV Evidence Tables
1. **User Action:** Clicks "Download PDF Case Dossier" or "Export CSV".
2. **Trigger:** Direct browser download link pointing to:
   - `/api/cases/{case_id}/export/report.pdf`
   - `/api/cases/{case_id}/export/entities.csv`
   - `/api/cases/{case_id}/export/artifacts.csv`
   - `/api/cases/{case_id}/export/analysis.csv`
3. **Behavior:** Browser triggers direct native file download.

---

## 6. Inputs Needing Special Frontend Handling

1. **Entity Selection Controls (Path & Timeline):**
   - The path endpoint fails with `404` if non-existent entity IDs are supplied. The frontend must cache the `nodes[].id` list from the graph response and render a searchable autocomplete dropdown.
2. **SHA-256 Hash Verification Display:**
   - Display hashes in monospace font (`font-mono`) with 1-click copy-to-clipboard buttons.
3. **Case Sensitivity in CSV Headers:**
   - The backend normalizers accept flexible headers (e.g. `caller_id`, `caller`, `source`), but CSV templates generated by the frontend should use standard canonical headers: `entity_id,name,phone,device_id,ip`.
4. **Persistence Guarantee:**
   - All cases ingested via `/upload-zip`, `/upload`, or `/load-demo` are persisted in **PostgreSQL / SQLite** (relational tables) and **Neo4j 5.20** (graph store). Data survives server and container restarts.

---

## 7. Known Gaps & Open Questions

1. **OCR on Scanned PDF FIRs:**
   - While `text_extractor.py` parses text-based PDFs and DOCX files directly, scanned image-only PDFs return an empty string and require OCR preprocessing. Frontend should advise users to provide text-based PDFs or raw text for best NLP performance.
2. **Real-time Push Notifications:**
   - The backend currently uses REST request/response. Real-time alert updates require client-side polling (e.g. polling `/alerts?status=PENDING` every 30 seconds). WebSockets are not currently exposed.
3. **Frontend Role Switching:**
   - In development mode, the frontend can pass custom `X-Role: ADMINISTRATOR` or `X-Role: INVESTIGATOR` headers to test role-gated UI elements without logging out and generating new OTPs.
