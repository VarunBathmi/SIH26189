from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import UserRole, CustodyLog, CaseRecord, CaseStatus
from app.security.auth import get_current_user, require_role
from app.cases.service import (
    create_case as create_case_svc,
    get_case_detail as get_case_detail_svc,
    update_case_status as update_case_status_svc,
    list_cases as list_cases_svc
)
from app.security.custody import verify_custody_chain
from app.graph.build_graph import get_case_graph
from app.graph.neo4j_engine import neo4j_engine
from app.forensics.zip_ingest import ingest_forensic_zip

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
@router.get("/cases/{case_id}/log", summary="Retrieve case custody audit log")
@router.get("/api/cases/{case_id}/log", summary="Retrieve case custody audit log (API alias)")
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
@router.get("/api/cases/{case_id}/graph", summary="Retrieve frontend-ready case graph (API alias)")
def get_case_graph_api(
    case_id: str,
    source: Optional[str] = Query("neo4j", description="Graph engine source: 'neo4j' or 'networkx'"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if source and source.lower() == "neo4j":
        return neo4j_engine.to_graph_json(case_id=case_id)
    return get_case_graph(cid=case_id)

@router.post("/cases/upload-zip", summary="Upload forensic evidence ZIP archive and ingest into Neo4j graph")
@router.post("/api/cases/upload-zip", summary="Upload forensic evidence ZIP archive (API alias)")
@router.post("/api/v1/cases/upload-zip", summary="Upload forensic evidence ZIP archive (API v1 alias)")
async def upload_case_zip(
    file: UploadFile = File(...),
    case_id: Optional[str] = Query(None, description="Optional target case ID override"),
    current_user: dict = Depends(require_role([UserRole.INVESTIGATOR, UserRole.ADMINISTRATOR])),
    db: Session = Depends(get_db)
):
    """
    Ingest a forensic evidence ZIP archive:
    - Normalizes CDR calls, chats, files, locations (with co-location), browser history, and entities
    - Verifies evidence integrity via SHA-256 pre-hashing
    - Persists records to database and case-scoped Neo4j graph
    - Returns case_id, entity/artifact counts, and non-fatal warnings
    """
    try:
        zip_bytes = await file.read()
        actor = current_user.get("email", "INVESTIGATOR")
        role = current_user.get("role", "INVESTIGATOR")
        result = ingest_forensic_zip(
            zip_bytes=zip_bytes,
            db=db,
            case_id_override=case_id,
            actor_id=actor,
            role=role
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Forensic ZIP ingestion error: {str(e)}")

@router.post("/cases/load-demo", summary="Load demo forensic investigation case")
@router.post("/api/cases/load-demo", summary="Load demo case (API alias)")
@router.post("/api/v1/cases/load-demo", summary="Load demo case (API v1 alias)")
def load_demo_case(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    demo_id = "CASE-DEMO-001"
    demo_data = {
        "case_id": demo_id,
        "title": "Operation Cyber Track Demo",
        "note": "Demo investigation case with synthetic forensic CDR & entity data",
        "entities": [
            {"entity_id": "P1", "name": "Rahul Sharma", "phone": "9990001", "device_id": "D1", "ip": "10.0.0.1"},
            {"entity_id": "P2", "name": "Amit Kumar", "phone": "9990002", "device_id": "D2", "ip": "10.0.0.2"},
            {"entity_id": "P3", "name": "Vikram Seth", "phone": "9990003", "device_id": "D3", "ip": "10.0.0.3"}
        ],
        "artifacts": [
            {"record_type": "call", "record_id": "CALL-DEMO-01", "caller_id": "P1", "callee_id": "P2", "duration_sec": 120, "timestamp": "2026-03-12T21:05:00"},
            {"record_type": "chat", "record_id": "CHAT-DEMO-01", "sender_id": "P2", "receiver_id": "P3", "platform": "Telegram", "timestamp": "2026-03-12T21:15:00"},
            {"record_type": "co_located", "record_id": "LOC-DEMO-01", "entity1": "P1", "entity2": "P2", "distance_km": 0.05, "timestamp": "2026-03-12T21:30:00"}
        ]
    }
    case_rec = db.query(CaseRecord).filter(CaseRecord.case_id == demo_id).first()
    if not case_rec:
        case_rec = CaseRecord(
            case_id=demo_id,
            case_number=demo_id,
            title=demo_data["title"],
            description=demo_data["note"],
            status=CaseStatus.OPEN.value,
            created_by=current_user.get("email")
        )
        db.add(case_rec)
        db.commit()
    neo4j_engine.load_case(demo_data)
    return {
        "status": "ok",
        "case_id": demo_id,
        "message": "Demo case loaded successfully",
        "entity_count": len(demo_data["entities"]),
        "artifact_count": len(demo_data["artifacts"])
    }

@router.get("/cases/{case_id}/centrality", summary="Retrieve centrality analytics for a case")
@router.get("/api/cases/{case_id}/centrality", summary="Retrieve centrality (API alias)")
@router.get("/api/v1/cases/{case_id}/centrality", summary="Retrieve centrality (API v1 alias)")
def get_case_centrality(
    case_id: str,
    current_user: dict = Depends(get_current_user)
):
    from app.graph.analytics import compute_pagerank, compute_betweenness_centrality, compute_investigative_priority_scores
    pr = compute_pagerank(case_id)
    bw = compute_betweenness_centrality(case_id)
    priority = compute_investigative_priority_scores(case_id)
    return {
        "case_id": case_id,
        "pagerank": pr,
        "betweenness": bw,
        "priority_scores": priority
    }

@router.get("/cases/{case_id}/timeline", summary="Retrieve chronological event timeline for a case")
@router.get("/api/cases/{case_id}/timeline", summary="Retrieve timeline (API alias)")
@router.get("/api/v1/cases/{case_id}/timeline", summary="Retrieve timeline (API v1 alias)")
def get_case_timeline(
    case_id: str,
    entity_id: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user)
):
    return neo4j_engine.timeline(case_id=case_id, entity_id=entity_id)

@router.get("/cases/{case_id}/path", summary="Compute shortest relationship path between two entities")
@router.get("/api/cases/{case_id}/path", summary="Compute path (API alias)")
@router.get("/api/v1/cases/{case_id}/path", summary="Compute path (API v1 alias)")
def get_case_path(
    case_id: str,
    source: str = Query(..., description="Source entity ID"),
    target: str = Query(..., description="Target entity ID"),
    current_user: dict = Depends(get_current_user)
):
    return neo4j_engine.shortest_path(case_id=case_id, source=source, target=target)

@router.get("/cases/{case_id}/export/report.pdf", summary="Export PDF report for a case")
@router.get("/api/cases/{case_id}/export/report.pdf", summary="Export PDF report (API alias)")
@router.get("/api/v1/cases/{case_id}/export/report.pdf", summary="Export PDF report (API v1 alias)")
def export_case_report_pdf(
    case_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    from app.api.forensics_routes import download_case_dossier_pdf
    return download_case_dossier_pdf(case_id=case_id, current_user=current_user, db=db)

class CaseUploadJSONPayload(BaseModel):
    case_id: Optional[str] = None
    title: Optional[str] = None
    note: Optional[str] = None
    entities: List[dict] = []
    artifacts: List[dict] = []

@router.post("/cases/upload", summary="Ingest case entities and forensic artifacts via JSON payload")
@router.post("/api/cases/upload", summary="Ingest case via JSON (API alias)")
@router.post("/api/v1/cases/upload", summary="Ingest case via JSON (API v1 alias)")
def upload_case_json(
    payload: CaseUploadJSONPayload,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    import uuid
    cid = (payload.case_id or f"CASE-{uuid.uuid4().hex[:8].upper()}").strip()
    if not payload.entities and not payload.artifacts:
        raise HTTPException(status_code=400, detail="Invalid payload: at least one entity or artifact is required.")

    case_rec = db.query(CaseRecord).filter(CaseRecord.case_id == cid).first()
    if not case_rec:
        case_rec = CaseRecord(
            case_id=cid,
            case_number=cid,
            title=payload.title or f"Investigation Case {cid}",
            description=payload.note or "Uploaded via JSON payload",
            status=CaseStatus.OPEN.value,
            created_by=current_user.get("email")
        )
        db.add(case_rec)
        db.commit()

    case_data = {
        "case_id": cid,
        "title": case_rec.title,
        "note": case_rec.description,
        "entities": payload.entities,
        "artifacts": payload.artifacts
    }
    result = neo4j_engine.load_case(case_data)
    return {
        "status": "ok",
        "case_id": cid,
        "entities_loaded": result.get("entities_loaded", len(payload.entities)),
        "artifacts_loaded": result.get("artifacts_loaded", len(payload.artifacts)),
        "message": f"Case {cid} ingested successfully."
    }

@router.get("/cases/{case_id}/export/entities.csv", summary="Export case entities as CSV")
@router.get("/api/cases/{case_id}/export/entities.csv", summary="Export entities CSV (API alias)")
def export_case_entities_csv(
    case_id: str,
    current_user: dict = Depends(get_current_user)
):
    from fastapi.responses import Response
    import io, csv
    graph_data = neo4j_engine.to_graph_json(case_id)
    nodes = graph_data.get("nodes", [])

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["entity_id", "label", "type", "name", "phone", "device_id", "ip"])
    for n in nodes:
        props = n.get("properties", {})
        writer.writerow([
            n.get("id", ""),
            n.get("label", ""),
            n.get("type", "Entity"),
            props.get("name", ""),
            props.get("phone", ""),
            props.get("device_id", ""),
            props.get("ip", "")
        ])
    return Response(content=output.getvalue(), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=entities_{case_id}.csv"})

@router.get("/cases/{case_id}/export/artifacts.csv", summary="Export case relationships/artifacts as CSV")
@router.get("/api/cases/{case_id}/export/artifacts.csv", summary="Export artifacts CSV (API alias)")
def export_case_artifacts_csv(
    case_id: str,
    current_user: dict = Depends(get_current_user)
):
    from fastapi.responses import Response
    import io, csv
    graph_data = neo4j_engine.to_graph_json(case_id)
    links = graph_data.get("links", [])

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["source", "target", "relation", "type", "timestamp", "record_id"])
    for l in links:
        props = l.get("properties", {})
        writer.writerow([
            l.get("source", ""),
            l.get("target", ""),
            l.get("relation", "RELATED"),
            l.get("type", "RELATED"),
            l.get("timestamp", props.get("timestamp", "")),
            props.get("record_id", "")
        ])
    return Response(content=output.getvalue(), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=artifacts_{case_id}.csv"})

@router.get("/cases/{case_id}/export/analysis.csv", summary="Export network analytics summary as CSV")
@router.get("/api/cases/{case_id}/export/analysis.csv", summary="Export analysis CSV (API alias)")
def export_case_analysis_csv(
    case_id: str,
    current_user: dict = Depends(get_current_user)
):
    from fastapi.responses import Response
    import io, csv
    from app.graph.analytics import compute_pagerank, compute_betweenness_centrality, compute_investigative_priority_scores
    pr = compute_pagerank(case_id)
    bw = compute_betweenness_centrality(case_id)
    priority = compute_investigative_priority_scores(case_id)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["entity_id", "pagerank", "betweenness_centrality", "priority_rank", "priority_score"])
    for item in priority.get("top_influencers", []):
        eid = item.get("id", "")
        writer.writerow([
            eid,
            item.get("pagerank", 0.0),
            item.get("betweenness", 0.0),
            item.get("priority_score", 0.0)
        ])
    return Response(content=output.getvalue(), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=analysis_{case_id}.csv"})

@router.get("/cases/{case_id}/export/report.pdf", summary="Export comprehensive case investigation dossier as PDF")
@router.get("/api/cases/{case_id}/export/report.pdf", summary="Export report PDF (API alias)")
def export_case_report_pdf(
    case_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    from fastapi.responses import FileResponse
    from app.forensics.report_generator import generate_case_pdf_dossier
    from app.graph.analytics import compute_investigative_priority_scores
    from app.models import EvidenceRecord, Alert

    case = db.query(CaseRecord).filter(CaseRecord.case_id == case_id).first()
    title = case.title if case else f"Investigation Case {case_id}"
    desc = case.description if case else "Forensic Network Investigation"
    status_str = case.status if case else "OPEN"
    created_by = case.created_by if case else current_user.get("email", "investigator@gov.in")
    created_at = case.created_at.isoformat() if (case and case.created_at) else None

    evidence_records = db.query(EvidenceRecord).filter(EvidenceRecord.case_id == case_id).all()
    evidence_list = [
        {
            "evidence_id": ev.evidence_id,
            "file_name": ev.file_name,
            "file_type": ev.file_type,
            "sha256_hash": ev.sha256_hash,
            "integrity_status": ev.integrity_status,
            "hash_created_at": ev.hash_created_at.isoformat() if ev.hash_created_at else None
        }
        for ev in evidence_records
    ]

    custody_info = verify_custody_chain(db=db, case_id=case_id)
    graph_analytics = compute_investigative_priority_scores(case_id=case_id, limit=10)

    alerts_records = db.query(Alert).filter(Alert.case_id == case_id).all()
    alerts_list = [
        {
            "alert_type": a.alert_type,
            "reason": a.reason,
            "status": a.status,
            "review_notes": a.review_notes
        }
        for a in alerts_records
    ]

    case_data = {
        "case_id": case_id,
        "title": title,
        "description": desc,
        "status": status_str,
        "created_by": created_by,
        "created_at": created_at
    }

    pdf_path = generate_case_pdf_dossier(
        case_data=case_data,
        evidence_list=evidence_list,
        custody_info=custody_info,
        graph_analytics=graph_analytics,
        alerts_list=alerts_list
    )

    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=f"Case_Report_{case_id}.pdf"
    )

@router.get("/cases/{case_id}/communities", summary="Retrieve detected communities / sub-cells in a case")
@router.get("/api/cases/{case_id}/communities", summary="Retrieve communities (API alias)")
@router.get("/api/v1/cases/{case_id}/communities", summary="Retrieve communities (API v1 alias)")
def get_case_communities(
    case_id: str,
    current_user: dict = Depends(get_current_user)
):
    from app.graph.analytics import detect_communities
    return detect_communities(case_id=case_id)

@router.get("/cases/{case_id}/anomalies", summary="Retrieve anomaly detection results for a case")
@router.get("/api/cases/{case_id}/anomalies", summary="Retrieve anomalies (API alias)")
@router.get("/api/v1/cases/{case_id}/anomalies", summary="Retrieve anomalies (API v1 alias)")
def get_case_anomalies(
    case_id: str,
    limit: int = Query(20, ge=1, le=100),
    current_user: dict = Depends(get_current_user)
):
    from app.graph.analytics import compute_investigative_priority_scores, detect_bridge_nodes
    scores = compute_investigative_priority_scores(case_id=case_id, limit=limit)
    bridges = detect_bridge_nodes(case_id=case_id)
    return {
        "case_id": case_id,
        "high_priority_anomalies": scores.get("top_influencers", []),
        "cut_vertices": bridges.get("cut_vertices", []),
        "bridge_edges": bridges.get("bridge_edges", [])
    }

@router.get("/cases/{case_id}/link-predictions", summary="Retrieve predicted associations for a case")
@router.get("/api/cases/{case_id}/link-predictions", summary="Retrieve link predictions (API alias)")
@router.get("/api/v1/cases/{case_id}/link-predictions", summary="Retrieve link predictions (API v1 alias)")
def get_case_link_predictions(
    case_id: str,
    limit: int = Query(10, ge=1, le=50),
    current_user: dict = Depends(get_current_user)
):
    from app.graph.analytics import predict_adamic_adar_links
    return predict_adamic_adar_links(case_id=case_id, top_k=limit)



