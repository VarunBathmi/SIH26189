from typing import Dict, Any
from sqlalchemy.orm import Session
from app.models import PersonMatch

def summarize_person_matches(db: Session, case_id: str) -> Dict[str, Any]:
    """
    Summarize candidate vs high confidence person matches discovered in a case.
    """
    matches = db.query(PersonMatch).filter(PersonMatch.case_id == case_id).all()

    high_confidence_count = 0
    formatted_matches = []

    for m in matches:
        is_high = m.matching_score >= 85.0 or "phone" in m.matching_reason.lower()
        if is_high:
            high_confidence_count += 1

        formatted_matches.append({
            "person1": m.person1,
            "person2": m.person2,
            "matching_score": m.matching_score,
            "matching_reason": m.matching_reason,
            "is_high_confidence": is_high
        })

    return {
        "case_id": case_id,
        "total_candidate_matches": len(matches),
        "high_confidence_matches": high_confidence_count,
        "matches": formatted_matches,
        "disclaimer": "Identity correlations indicate string and contact similarity for investigator validation."
    }
