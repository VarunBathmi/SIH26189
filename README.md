# AI-Powered Criminal Network Analysis Platform
### Master Backend Blueprint — PS 26189 Aligned (v4.0.0)
**Ministry of Home Affairs / NCRB, Women Safety Division**

---

## 📑 Overview
The **AI-Powered Criminal Network Analysis Platform** is an enterprise-grade investigative decision-support and early-warning system. It ingests raw unstructured narrative reports (FIRs, Surveillance, Intelligence Agency reports, Social Media intelligence), extracts structured entities and events (calls, illicit financial flows, physical meetings), constructs multi-layered network graphs, and maintains a tamper-evident **Digital Chain of Custody (SHA-256 Hash Chain)** and **Professional Evidence Integrity Verification Module**.

---

## 🛡️ Core Guardrails & Ethical Compliance (PS 26189)

1. **Decision-Support / Non-Predictive Architecture**:
   - The platform never claims to predict future criminality.
   - All network metrics are calculated as an **Investigative Priority Score (0–100)** reflecting structural centrality and pattern frequency only.
   - Every API response returns a mandatory ethical compliance disclaimer.
2. **Dual-Authorization Identity Reveal ("Four-Eyes Principle")**:
   - Real suspect PII is encrypted with Fernet (AES-128-CBC + HMAC-SHA256) and never stored in plain text in public graph nodes.
   - Decryption requires independent approvals from both an `ADMINISTRATOR` and a distinct `INVESTIGATOR`.
   - Requesters are strictly prohibited from self-approving their own unmasking requests.
3. **Digital Chain of Custody (Verifiable Hash Chain)**:
   - Maintains an append-only `custody_log` where each record's `current_hash = SHA256(case_id + action + canonical_details + prev_hash + timestamp)`.
   - Genesis starts from `"0" * 64`.
   - Endpoint `GET /api/v1/cases/{case_id}/custody/verify` verifies continuity and recomputes hashes to detect any tampering.
4. **Cryptographic Evidence Integrity**:
   - Binary SHA-256 hashing computed directly from actual file bytes upon upload.
   - Deterministic visual symbol blocks (`▓░▒▓ ▒▒▓▒...`) and 4x4 hex matrix for human scannability.
   - On-demand verification (`POST /api/evidence/{id}/verify`) flags evidence as `VERIFIED` or `COMPROMISED` without silently overwriting the original recorded fingerprint.
5. **Human-in-the-Loop Alert Workflow**:
   - Automated detectors (Call Bursts, Smurfing/Structuring, Co-Location) default to status `PENDING`.
   - Only authorized officers can confirm or dismiss alerts, with every disposition recorded in the audit log.

---

## 🏗️ Architecture

```
                    EXTERNAL FRONTEND (Next.js UI)
                                │
                                ▼ REST / JSON over HTTP
┌────────────────────────────────────────────────────────────────────────┐
│                        FASTAPI BACKEND ENGINE                          │
│                                                                        │
│  [NLP Event & Entity Engine]       [Digital Forensics & Co-Location]   │
│  [Financial Smurfing Detector]     [Digital Chain of Custody (SHA-256)]│
│  [Evidence Integrity Engine]       [Dual-Auth PII Reveal & RBAC]       │
│  [Graph Analytics (PageRank/BW)]   [Unified Alert Management]          │
└───────────────────┬────────────────────────────────┬───────────────────┘
                    │                                │
                    ▼ SQLAlchemy(ORM)                ▼ Neo4j Bolt / NetworkX
┌──────────────────────────────────────┐  ┌──────────────────────────────┐
│        POSTGRESQL 15 DATABASE        │  │     NEO4J 5.20 / NETWORKX    │
│ case_records, document_records,      │  │ Nodes: Person, Organization, │
│ evidence_records, custody_log,       │  │ Location, Case, Device, File │
│ call_records, transaction_records,   │  │ Edges: CALLED, TRANSACTED_   │
│ alerts, entity_lookup, audit_log     │  │ WITH, AFFILIATED_WITH, etc.  │
└──────────────────────────────────────┘  └──────────────────────────────┘
```

---

## 🚀 Quick Start Guide

### Option 1: Run with Docker Compose (Recommended)
```bash
# 1. Clone or navigate to the workspace
cd SIH26189

# 2. Build and start PostgreSQL, Neo4j, and FastAPI backend
docker compose up -d --build

# 3. Verify container status
docker compose ps
```

### Option 2: Run Locally (Python 3.12)
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Seed realistic demo investigation data
python scripts/seed_demo_data.py

# 3. Start FastAPI ASGI dev server
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## 🧪 Running Automated Tests

Run the complete test suite (21 unit and integration tests):
```bash
pytest -v
```

Test coverage includes:
- `tests/test_nlp.py`: Transformer entity extraction (including `ORGANIZATION`), `CALL` and `TRANSACTION` event slot-filling, fuzzy person matching, call burst detection.
- `tests/test_financial.py`: Money laundering structuring/smurfing detection, large amount thresholds.
- `tests/test_custody.py`: Genesis hash `"0"*64`, hash continuity, chronological tampering detection.
- `tests/test_evidence_integrity.py`: Standard SHA-256 test vectors, 1-byte alteration detection, visual symbol determinism, lifecycle verification.
- `tests/test_security.py`: Fernet PII encryption roundtrip, deterministic pseudonymization.
- `tests/test_forensics.py`: Path-traversal safe ZIP analysis, provenance checking, Haversine co-location, ReportLab PDF dossier generation.
- `tests/test_graph_analytics.py`: Multi-label Neo4j/NetworkX graph writing, PageRank, betweenness centrality, bridge nodes, Louvain communities, 7-dimension Priority Score.
- `tests/test_api_endpoints.py`: End-to-end API integration tests and dual-authorization workflow.

---

## 📡 API Endpoint Catalog

### 1. Ingestion & Evidence
- `POST /ingestion/report`: Ingest raw narrative text (FIR, Surveillance, Intel Report), extract entities and events, update graph, return `graph_delta`.
- `POST /ingestion/upload-forensic-zip`: Safely unpack evidence ZIP, compute SHA-256 hashes, verify provenance.
- `POST /api/evidence/upload`: Register digital evidence file, compute binary SHA-256 fingerprint, format visual symbols.
- `GET /api/evidence/{id}`: Retrieve evidence metadata, visual symbols, and verification status.
- `GET /api/evidence/{id}/hash`: Retrieve SHA-256 fingerprint.
- `POST /api/evidence/{id}/verify`: Re-read binary bytes from disk and verify against immutable recorded fingerprint.
- `GET /api/evidence/{id}/custody`: Retrieve custody history for specific evidence item.

### 2. Case Management & Chain of Custody
- `POST /cases`: Create new investigation case.
- `GET /cases?status=OPEN,IN_PROGRESS`: List cases with status filter.
- `GET /cases/{case_id}`: Retrieve case details and summary metrics.
- `PATCH /cases/{case_id}/status`: Update case lifecycle status (`OPEN` → `IN_PROGRESS` → `COMPLETED` → `CLOSED`).
- `GET /api/v1/cases/{case_id}/custody`: Retrieve chronological hash chain.
- `GET /api/v1/cases/{case_id}/custody/verify`: Cryptographically verify Chain of Custody.
- `GET /api/v1/cases/{case_id}/graph`: Retrieve frontend-ready case network graph.

### 3. Graph Analytics & Priority Scoring
- `GET /graph/overview?case_id=`: Full case graph (Cytoscape / Vis.js compatible).
- `GET /graph/person/{hash_id}`: Ego-network for a specific entity.
- `GET /graph/shortest-path?source=&target=&case_id=`: Shortest path between two entities.
- `GET /graph/top-influencers?case_id=&limit=`: PageRank, betweenness, and 7-dimension Priority Score.
- `GET /graph/communities?case_id=`: Louvain community detection for hidden sub-cells.
- `GET /graph/bridge-nodes?case_id=`: Cut-vertices and structural brokers.
- `GET /graph/predicted-links?case_id=`: Adamic-Adar link predictions.

### 4. Rollup Analytics
- `GET /analytics/time?case_id=`: Activity by hour, day of week, nocturnal count, timeline.
- `GET /analytics/calls?case_id=`: Call communication totals, average duration, longest call, burst counts.
- `GET /analytics/transactions?case_id=`: Total amount moved, largest transaction, smurfing flags, timeline.
- `GET /analytics/person-matches?case_id=`: Candidate vs high-confidence identity matches.

### 5. Alerts & Human Verification
- `GET /alerts?case_id=&status=`: Unified alert feed.
- `POST /alerts/{id}/confirm`: Human confirmation of automated alert into an investigative lead.
- `POST /alerts/{id}/dismiss`: Human dismissal of false positive.

### 6. Security & Dual-Authorization
- `POST /secure/reveal-request`: Submit identity unmasking request.
- `POST /secure/reveal-request/{id}/approve`: Record role approval (requires 1 Admin + 1 distinct Investigator).
- `POST /secure/reveal-request/{id}/reject`: Reject reveal request.
- `GET /secure/reveal-request/{id}`: Fetch status (`real_name` exposed ONLY if status is `APPROVED`).
- `GET /audit/events`: Query immutable audit ledger.
- `GET /forensics/cases/{case_id}/pdf`: Generate and download PDF Case Dossier.

---

## 🎨 Frontend Integration Notes (For UI Teammate)
- **Base URL**: `http://localhost:8000` (configurable via `NEXT_PUBLIC_API_URL`).
- **Auth Header**: Send `Authorization: Bearer <token>` or use `X-Role: investigator` during local testing.
- **Immediate Graph Rendering**: `POST /ingestion/report` returns `graph_delta.nodes_added` and `graph_delta.edges_added` so you can animate new nodes instantly without re-fetching the entire graph.
- **Visual Hash Display**: `GET /api/evidence/{id}` returns both `formatted_blocks` (4x4 hex matrix) and `visual_symbols` (`▓░▒▓ ▒▒▓▒...`) ready to display in an Evidence Integrity badge.
- **Investigator Inbox**: Poll `GET /alerts?case_id=...&status=PENDING` to populate the unreviewed alerts feed.
#   S I H 2 6 1 8 9  
 