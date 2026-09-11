from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app.security.auth import get_current_user
from app.analytics.time_analysis import analyze_case_timeline
from app.analytics.call_analysis import analyze_case_calls
from app.analytics.transaction_analysis import analyze_case_transactions
from app.analytics.person_match_summary import summarize_person_matches

router = APIRouter(prefix="/analytics", tags=["Case Intelligence & Rollup Analytics"])

@router.get("/time", summary="Retrieve timeline analysis, hour distribution, and nocturnal activity patterns")
def get_time_analytics(
    case_id: str = Query(..., description="Case ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return analyze_case_timeline(db=db, case_id=case_id)

@router.get("/calls", summary="Retrieve aggregate call communications rollup and burst counts")
def get_call_analytics(
    case_id: str = Query(..., description="Case ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return analyze_case_calls(db=db, case_id=case_id)

@router.get("/transactions", summary="Retrieve aggregate financial flows and transaction timeline")
def get_transaction_analytics(
    case_id: str = Query(..., description="Case ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return analyze_case_transactions(db=db, case_id=case_id)

@router.get("/person-matches", summary="Retrieve candidate vs high-confidence person identity match rollup")
def get_person_match_analytics(
    case_id: str = Query(..., description="Case ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return summarize_person_matches(db=db, case_id=case_id)
