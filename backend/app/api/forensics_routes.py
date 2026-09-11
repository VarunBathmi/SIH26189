from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import UserRole, CaseRecord, EvidenceRecord, Alert
from app.security.auth import require_role
from app.security.custody import verify_custody_chain
from app.graph.analytics import compute_investigative_priority_scores
from app.forensics.report_generator import generate_case_pdf_dossier

router = APIRouter(prefix="/forensics", tags=["Forensic Dossiers & PDF Reports"])

@router.get("/cases/{case_id}/pdf", summary="Generate and download comprehensive PDF Case Dossier with Evidence Integrity Matrix")
def download_case_dossier_pdf(
    case_id: str,
    current_user: dict = Depends(require_role([UserRole.INVESTIGATOR, UserRole.ADMINISTRATOR])),
    db: Session = Depends(get_db)
):
    case = db.query(CaseRecord).filter(CaseRecord.case_id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    # 1. Fetch case evidence
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

    # 2. Fetch chain of custody verification
    custody_info = verify_custody_chain(db=db, case_id=case_id)

    # 3. Fetch network analytics
    graph_analytics = compute_investigative_priority_scores(case_id=case_id, limit=10)

    # 4. Fetch alerts
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
        "case_id": case.case_id,
        "title": case.title,
        "description": case.description,
        "status": case.status,
        "created_by": case.created_by,
        "created_at": case.created_at.isoformat() if case.created_at else None
    }

    try:
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
            filename=f"Case_Dossier_{case_id}.pdf"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF dossier: {str(e)}")
