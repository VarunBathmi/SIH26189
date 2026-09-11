import re
import datetime
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

def parse_call_hour(timestamp_str: str) -> int:
    """Extract hour (0-23) from timestamp string."""
    if not timestamp_str:
        return 12
    # Match time format like 23:40 or 11:40 PM
    match_24 = re.search(r"\b(\d{1,2}):(\d{2})\b", timestamp_str)
    match_ampm = re.search(r"\b(\d{1,2})(?::(\d{2}))?\s*(AM|PM)\b", timestamp_str, re.IGNORECASE)
    
    if match_ampm:
        h = int(match_ampm.group(1))
        meridiem = match_ampm.group(3).upper()
        if meridiem == "PM" and h < 12:
            h += 12
        elif meridiem == "AM" and h == 12:
            h = 0
        return h
    elif match_24:
        return int(match_24.group(1)) % 24
    return 12

def detect_suspicious_calls(
    calls: List[Dict[str, Any]],
    long_duration_threshold_sec: int = 300,
    burst_count_threshold: int = 3
) -> List[Dict[str, Any]]:
    """
    Detect suspicious call communication patterns:
    1. Long duration calls (>= 300s / 5 mins)
    2. Nocturnal activity (calls between 00:00 and 05:00)
    3. Repeated contact burst (>= 3 calls between same pair)
    """
    flagged_calls = []
    pair_counts = {}

    for c in calls:
        p1 = c.get("caller", "")
        p2 = c.get("callee", "")
        pair_key = tuple(sorted([p1, p2]))
        pair_counts[pair_key] = pair_counts.get(pair_key, 0) + 1

    for c in calls:
        reasons = []
        duration = c.get("duration_sec", 0)
        timestamp = c.get("timestamp", "")
        caller = c.get("caller", "")
        callee = c.get("callee", "")
        pair_key = tuple(sorted([caller, callee]))

        if duration >= long_duration_threshold_sec:
            reasons.append(f"long_duration ({duration}s)")

        hour = parse_call_hour(timestamp)
        if 0 <= hour <= 5:
            reasons.append(f"nocturnal_activity ({timestamp})")

        if pair_counts.get(pair_key, 0) >= burst_count_threshold:
            reasons.append(f"repeated_contact_burst ({pair_counts[pair_key]} calls)")

        if reasons:
            flagged_calls.append({
                "call_id": c.get("call_id", "EXTRACTED_CALL"),
                "caller": caller,
                "callee": callee,
                "duration_sec": duration,
                "timestamp": timestamp,
                "reasons": reasons,
                "confidence": "requires_investigator_review"
            })

    return flagged_calls
