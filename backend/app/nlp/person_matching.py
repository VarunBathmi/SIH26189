import logging
from typing import Optional, Dict, Any, List
from rapidfuzz import fuzz

logger = logging.getLogger(__name__)

def match_person(
    name1: str,
    name2: str,
    phone1: Optional[str] = None,
    phone2: Optional[str] = None
) -> Dict[str, Any]:
    """
    Cross-document person fuzzy matching:
    Evaluates name token similarity and phone number correlation.
    """
    n1 = name1.strip().lower()
    n2 = name2.strip().lower()

    # Exact match
    if n1 == n2:
        return {
            "match": True,
            "score": 100.0,
            "reason": "exact_name_match",
            "is_high_confidence": True
        }

    # Phone number match
    phone_matched = False
    if phone1 and phone2 and phone1.strip() and phone2.strip():
        p1 = phone1.strip().replace("+91", "").replace("-", "").replace(" ", "")
        p2 = phone2.strip().replace("+91", "").replace("-", "").replace(" ", "")
        if p1 == p2:
            phone_matched = True

    token_score = float(fuzz.token_set_ratio(n1, n2))

    reasons = []
    if phone_matched:
        reasons.append("phone_number_match")
    if token_score >= 85:
        reasons.append(f"high_name_similarity ({token_score:.1f}%)")
    elif token_score >= 70:
        reasons.append(f"moderate_name_similarity ({token_score:.1f}%)")

    # Weighted scoring
    if phone_matched and token_score >= 70:
        final_score = 100.0
        is_high = True
    elif phone_matched:
        final_score = 90.0
        is_high = True
    elif token_score >= 85:
        final_score = token_score
        is_high = True
    elif token_score >= 70:
        final_score = token_score
        is_high = False
    else:
        final_score = token_score
        is_high = False

    is_match = final_score >= 70.0

    return {
        "match": is_match,
        "score": final_score,
        "reason": ", ".join(reasons) if reasons else "low_similarity",
        "is_high_confidence": is_high
    }
