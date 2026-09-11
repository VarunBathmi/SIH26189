import re
import logging
from typing import Optional, Dict, Any, List, Tuple
from rapidfuzz import fuzz

logger = logging.getLogger(__name__)

HONORIFICS_REGEX = re.compile(
    r"\b(?:shri|shree|smt|dr|mr|mrs|ms|mohd|md|adv|inspector|late|alias|aka|a\.k\.a)\b\.?",
    re.IGNORECASE
)

def normalize_person_name(name: str) -> str:
    """
    Clean and normalize an individual's name for robust matching:
    - Strips honorifics, titles, and alias prefixes
    - Removes non-alphanumeric punctuation (except spaces)
    - Condenses multiple whitespace runs
    """
    if not name:
        return ""
    # Strip honorifics
    cleaned = HONORIFICS_REGEX.sub("", name)
    # Remove commas, quotes, hyphens
    cleaned = re.sub(r"[^\w\s]", " ", cleaned)
    # Normalize whitespace and lowercase
    return " ".join(cleaned.lower().split())

def match_person(
    name1: str,
    name2: str,
    phone1: Optional[str] = None,
    phone2: Optional[str] = None,
    additional_attributes: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Evaluate cross-document person matching with investigative integrity.
    Distinguishes strictly between CONFIRMED_MATCH and POSSIBLE_MATCH (requiring review).

    Matching dimensions:
    1. Exact Name Equality (100%) -> CONFIRMED_MATCH
    2. Phone Correlation + High Token Similarity (>= 70%) -> CONFIRMED_MATCH (100%)
    3. Sole Phone Match -> CONFIRMED_MATCH (90%)
    4. Initials / Token Variation (e.g., 'Rahul Sharma' vs 'Rahul S.' / 'R. Sharma') -> POSSIBLE_MATCH / CONFIRMED
    5. Token Similarity (70-84%) -> POSSIBLE_MATCH (Requires Investigator Review)
    6. Low Similarity (< 70%) -> NO_MATCH
    """
    raw_n1 = name1.strip()
    raw_n2 = name2.strip()
    norm1 = normalize_person_name(raw_n1)
    norm2 = normalize_person_name(raw_n2)

    if not norm1 or not norm2:
        return {
            "match": False,
            "status": "NO_MATCH",
            "score": 0.0,
            "reason": "empty_name_string",
            "is_high_confidence": False,
            "requires_human_review": False
        }

    # 1. Exact Equality
    if norm1 == norm2:
        return {
            "match": True,
            "status": "CONFIRMED_MATCH",
            "score": 100.0,
            "reason": "exact_name_match",
            "is_high_confidence": True,
            "requires_human_review": False
        }

    # 2. Phone Number Comparison
    phone_matched = False
    if phone1 and phone2:
        p1 = re.sub(r"\D", "", phone1)
        p2 = re.sub(r"\D", "", phone2)
        # Check last 10 digits
        if len(p1) >= 10 and len(p2) >= 10 and p1[-10:] == p2[-10:]:
            phone_matched = True

    # 3. Fuzzy Metrics
    token_score = float(fuzz.token_set_ratio(norm1, norm2))
    partial_score = float(fuzz.partial_ratio(norm1, norm2))

    # Check for initials match (e.g., "Rahul Sharma" and "R Sharma" or "Rahul S")
    tokens1 = norm1.split()
    tokens2 = norm2.split()
    is_initials_variant = False
    if len(tokens1) >= 2 and len(tokens2) >= 2:
        first_init_match = tokens1[0][0] == tokens2[0][0]
        last_match = tokens1[-1] == tokens2[-1]
        if first_init_match and last_match:
            is_initials_variant = True

    reasons = []
    if phone_matched:
        reasons.append("phone_number_match")
    if is_initials_variant:
        reasons.append("name_initials_variation")
    if token_score >= 85:
        reasons.append(f"high_token_similarity ({token_score:.1f}%)")
    elif token_score >= 70:
        reasons.append(f"moderate_token_similarity ({token_score:.1f}%)")

    # Final Classification Logic
    if phone_matched and (token_score >= 70 or is_initials_variant):
        final_score = 100.0
        status = "CONFIRMED_MATCH"
        is_high = True
        needs_review = False
    elif phone_matched:
        final_score = 90.0
        status = "CONFIRMED_MATCH"
        is_high = True
        needs_review = True
    elif is_initials_variant and (token_score >= 70 or partial_score >= 85):
        final_score = max(token_score, 88.0)
        status = "POSSIBLE_MATCH"
        is_high = False
        needs_review = True
    elif token_score >= 85:
        final_score = token_score
        status = "POSSIBLE_MATCH" if token_score < 95 else "CONFIRMED_MATCH"
        is_high = token_score >= 95
        needs_review = token_score < 95
    elif token_score >= 70:
        final_score = token_score
        status = "POSSIBLE_MATCH"
        is_high = False
        needs_review = True
    else:
        final_score = token_score
        status = "NO_MATCH"
        is_high = False
        needs_review = False

    is_match = status in ("CONFIRMED_MATCH", "POSSIBLE_MATCH")

    return {
        "match": is_match,
        "status": status,
        "score": round(final_score, 1),
        "reason": ", ".join(reasons) if reasons else "insufficient_similarity",
        "is_high_confidence": is_high,
        "requires_human_review": needs_review
    }

def resolve_case_identities(
    persons: List[str],
    phone_map: Optional[Dict[str, str]] = None,
    case_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Scan all extracted persons within a case and identify candidate duplicate identities.
    Returns reviewable suggestions for human investigators without destructive auto-merges.
    """
    if not persons or len(persons) < 2:
        return []

    unique_persons = list(dict.fromkeys(persons))
    phone_map = phone_map or {}
    candidate_matches = []
    seen_pairs = set()

    for i in range(len(unique_persons)):
        for j in range(i + 1, len(unique_persons)):
            p1 = unique_persons[i]
            p2 = unique_persons[j]
            pair_key = tuple(sorted([p1, p2]))
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)

            match_res = match_person(
                name1=p1,
                name2=p2,
                phone1=phone_map.get(p1),
                phone2=phone_map.get(p2)
            )

            if match_res["match"]:
                candidate_matches.append({
                    "case_id": case_id or "CASE-CURRENT",
                    "person1": p1,
                    "person2": p2,
                    "status": match_res["status"],
                    "score": match_res["score"],
                    "reason": match_res["reason"],
                    "requires_review": match_res["requires_human_review"],
                    "recommendation": (
                        f"Investigator review recommended: Potential duplicate identity between '{p1}' and '{p2}' "
                        f"({match_res['reason']}, Score: {match_res['score']}%)"
                    )
                })

    return candidate_matches
