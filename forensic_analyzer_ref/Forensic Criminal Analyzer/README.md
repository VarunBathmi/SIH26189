# Forensic Criminal Analyzer

An AI-assisted **entity-relationship analysis tool for digital forensics** —
ingests device artifact metadata (call logs, chat metadata, browser history,
file transfer records) and builds an interactive graph to help an analyst
find hidden connections between entities.

**This is an investigative aid, not an automated decision system.** Every
score it produces (anomaly score, centrality, predicted link) is a triage
signal for a human analyst to review — it never makes a determination of
guilt or involvement. It ships with a synthetic (fully fake) dataset for
testing/demo purposes; no real case data is included.

## What it does

- **Graph construction** — turns raw artifacts into an entity network (people,
  devices, phones) with typed edges (call / chat / file transfer / co-location)
- **Centrality analysis** — degree, betweenness, eigenvector centrality to
  find hubs and likely intermediaries
- **Community detection** — greedy modularity clustering to surface likely
  groups
- **Anomaly scoring** — Isolation Forest over behavioral features (degree,
  edge volume, artifact diversity, off-hour activity ratio) as a triage
  signal
- **Link prediction** — Adamic-Adar index to suggest probable-but-unconfirmed
  connections
- **Path finder** — shortest path between any two entities ("how is A
  connected to B")
- **Co-location detection** — flags entities whose location pings place them
  near each other within a short time window (haversine distance + time
  windowing), a real geolocation-forensics technique
- **Timeline view** — chronological feed of every artifact, filterable to a
  single entity
- **Report export** — one-click PDF case summary and CSV exports (entities,
  artifacts, analysis scores) for hand-off to an analyst
- **Chain-of-custody log** — every analytical action is timestamped and
  logged, matching how real forensic tools track analyst activity

## Stack

- **Backend**: Flask + NetworkX (graph engine) + scikit-learn (anomaly
  detection) + ReportLab (PDF export), in-memory case store, gunicorn for
  production serving
- **Frontend**: React + Vite + react-force-graph-2d for the interactive graph
- **Tests**: pytest — 32 tests covering the graph engine and API (unit +
  integration)

## Running it

### Backend
```bash
cd backend
pip install -r requirements.txt
python3 run.py
# serves on http://localhost:5000
```

Run the test suite:
```bash
cd backend
pytest
```

### Frontend
```bash
cd frontend
npm install
npm run dev
# serves on http://localhost:5173, proxies /api to the Flask backend
```

Open http://localhost:5173, click **"Load synthetic demo case"**, and
explore the graph and analysis tabs.

**Want it live on a public URL, or running with one Docker command?**
See [`DEPLOY.md`](./DEPLOY.md).

## Bringing your own data

Upload a JSON file shaped like `backend/data/synthetic_case_demo001.json`:

```json
{
  "case_id": "MY-CASE",
  "entities": [
    {"entity_id": "P001", "name": "...", "phone": "...", "device_id": "...", "ip": "..."}
  ],
  "artifacts": [
    {"record_type": "call", "record_id": "...", "caller_id": "P001", "callee_id": "P002",
     "duration_sec": 120, "timestamp": "2026-08-01T14:00:00"},
    {"record_type": "chat", "record_id": "...", "sender_id": "P001", "receiver_id": "P003",
     "platform": "...", "timestamp": "..."},
    {"record_type": "file_artifact", "record_id": "...", "owner_id": "P002",
     "device_id": "...", "filename": "...", "hash_sha256": "...", "timestamp": "...",
     "transferred_to_id": "P004"},
    {"record_type": "location_ping", "record_id": "...", "entity_id": "P001",
     "device_id": "...", "lat": 12.9716, "lng": 77.5946, "timestamp": "..."}
  ]
}
```

Regenerate the synthetic demo dataset any time with:
```bash
cd backend/data && python3 generate_synthetic_data.py
```

## Notes on scope

This is a portfolio/demo-grade tool. For real casework it would need: a
persistent database instead of the in-memory case store, authentication/RBAC,
encrypted-at-rest storage for uploaded artifacts, and a documented chain-of-
custody export format suitable for evidentiary use.
