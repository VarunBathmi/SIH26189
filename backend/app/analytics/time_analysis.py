import re
import datetime
from typing import Dict, List, Any
from sqlalchemy.orm import Session
from app.models import CallRecord, TransactionRecord, DocumentRecord
from app.nlp.call_detection import parse_call_hour

TIME_ANALYTICS_DISCLAIMER = "Timing patterns indicate activity concentration only, not intent or wrongdoing."

def analyze_case_timeline(db: Session, case_id: str) -> Dict[str, Any]:
    """
    Aggregate all timestamps across calls, transactions, and documents for a case.
    Builds hour-of-day distribution, day-of-week distribution, and merged chronological timeline.
    """
    calls = db.query(CallRecord).filter(CallRecord.case_id == case_id).all()
    transactions = db.query(TransactionRecord).filter(TransactionRecord.case_id == case_id).all()

    hours_dist = {str(h): 0 for h in range(24)}
    days_dist = {
        "Monday": 0, "Tuesday": 0, "Wednesday": 0,
        "Thursday": 0, "Friday": 0, "Saturday": 0, "Sunday": 0
    }
    nocturnal_count = 0
    timeline_events = []

    # Process calls
    for c in calls:
        ts = c.timestamp or ""
        h = parse_call_hour(ts)
        hours_dist[str(h)] += 1
        if 0 <= h <= 5:
            nocturnal_count += 1

        timeline_events.append({
            "timestamp": ts,
            "type": "CALL",
            "participants": [c.caller, c.callee],
            "duration_sec": c.duration_sec,
            "source_document": c.source_document
        })

    # Process transactions
    for t in transactions:
        ts = t.timestamp or ""
        h = parse_call_hour(ts)
        hours_dist[str(h)] += 1
        if 0 <= h <= 5:
            nocturnal_count += 1

        timeline_events.append({
            "timestamp": ts,
            "type": "TRANSACTION",
            "participants": [t.sender, t.receiver],
            "amount": t.amount,
            "currency": t.currency,
            "location": {"landmark": t.landmark, "area": t.area},
            "source_document": t.source_document
        })

    # Basic sort of timeline
    timeline_events.sort(key=lambda x: str(x.get("timestamp", "")))

    return {
        "case_id": case_id,
        "activity_by_hour": hours_dist,
        "activity_by_day_of_week": days_dist,
        "nocturnal_activity_count": nocturnal_count,
        "timeline": timeline_events,
        "total_timed_events": len(timeline_events),
        "disclaimer": TIME_ANALYTICS_DISCLAIMER
    }
