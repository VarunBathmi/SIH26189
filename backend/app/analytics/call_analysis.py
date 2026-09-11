from typing import Dict, Any
from sqlalchemy.orm import Session
from app.models import CallRecord, Alert
from app.nlp.call_detection import parse_call_hour

def analyze_case_calls(db: Session, case_id: str) -> Dict[str, Any]:
    """
    Compute aggregate call analytics and communication patterns for a case.
    """
    calls = db.query(CallRecord).filter(CallRecord.case_id == case_id).all()
    if not calls:
        return {
            "case_id": case_id,
            "total_calls": 0,
            "average_duration_sec": 0,
            "longest_call": None,
            "most_frequent_pair": None,
            "nocturnal_call_count": 0,
            "burst_flags_pending_review": 0,
            "disclaimer": "Call patterns indicate communication volume and duration only."
        }

    total_duration = sum(c.duration_sec for c in calls)
    avg_duration = total_duration / len(calls)
    longest = max(calls, key=lambda c: c.duration_sec)

    pair_counts = {}
    nocturnal_count = 0

    for c in calls:
        pair = tuple(sorted([c.caller, c.callee]))
        pair_counts[pair] = pair_counts.get(pair, 0) + 1
        h = parse_call_hour(c.timestamp or "")
        if 0 <= h <= 5:
            nocturnal_count += 1

    top_pair = max(pair_counts.items(), key=lambda x: x[1]) if pair_counts else None

    pending_bursts = db.query(Alert).filter(
        Alert.case_id == case_id,
        Alert.alert_type == "CALL_BURST",
        Alert.status == "PENDING"
    ).count()

    return {
        "case_id": case_id,
        "total_calls": len(calls),
        "average_duration_sec": round(avg_duration, 1),
        "longest_call": {
            "caller": longest.caller,
            "callee": longest.callee,
            "duration_sec": longest.duration_sec,
            "timestamp": longest.timestamp
        } if longest else None,
        "most_frequent_pair": {
            "person_a": top_pair[0][0],
            "person_b": top_pair[0][1],
            "call_count": top_pair[1]
        } if top_pair else None,
        "nocturnal_call_count": nocturnal_count,
        "burst_flags_pending_review": pending_bursts,
        "disclaimer": "Call patterns indicate communication volume and duration only."
    }
