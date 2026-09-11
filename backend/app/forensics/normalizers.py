import csv
import io
import math
import uuid
import datetime
import logging
from typing import Dict, List, Any, Tuple, Optional

logger = logging.getLogger(__name__)

def _get_val(row: Dict[str, Any], candidate_keys: List[str], default: Any = "") -> Any:
    """Helper to retrieve value from a dict case-insensitively across multiple possible alias column names."""
    lower_map = {k.strip().lower(): v for k, v in row.items() if k is not None}
    for cand in candidate_keys:
        cand_lower = cand.strip().lower()
        if cand_lower in lower_map and lower_map[cand_lower] is not None:
            val = str(lower_map[cand_lower]).strip()
            if val:
                return val
    return default

def _get_int(row: Dict[str, Any], candidate_keys: List[str], default: int = 0) -> int:
    val = _get_val(row, candidate_keys, "")
    try:
        return int(float(val))
    except (ValueError, TypeError):
        return default

def _get_float(row: Dict[str, Any], candidate_keys: List[str], default: float = 0.0) -> float:
    val = _get_val(row, candidate_keys, "")
    try:
        return float(val)
    except (ValueError, TypeError):
        return default

def _parse_csv_rows(csv_text: str) -> List[Dict[str, Any]]:
    """Parse CSV text with comma or tab delimiter detection."""
    sample = csv_text[:2048]
    delimiter = "\t" if "\t" in sample and "," not in sample else ","
    f = io.StringIO(csv_text.strip())
    reader = csv.DictReader(f, delimiter=delimiter)
    return [row for row in reader if any(v and v.strip() for v in row.values() if v is not None)]

def normalize_calls_csv(csv_text: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Normalize CDR / Call logs CSV export.
    Returns: (list_of_call_artifacts, list_of_warnings)
    """
    artifacts = []
    warnings = []
    rows = _parse_csv_rows(csv_text)

    for idx, row in enumerate(rows, start=1):
        caller = _get_val(row, ["caller", "caller_id", "from", "source", "originator"])
        callee = _get_val(row, ["callee", "callee_id", "to", "target", "dialed_number", "destination"])
        timestamp = _get_val(row, ["timestamp", "time", "date_time", "datetime", "call_time", "date"])
        duration_sec = _get_int(row, ["duration_sec", "duration", "call_duration", "seconds", "len"])
        record_id = _get_val(row, ["record_id", "id", "call_id", "cdr_id"]) or f"CALL-{uuid.uuid4().hex[:6].upper()}"

        if not caller or not callee:
            warnings.append(f"Row {idx} in calls.csv missing caller or callee ({row})")
            continue

        artifacts.append({
            "record_type": "call",
            "record_id": record_id,
            "caller_id": caller,
            "callee_id": callee,
            "duration_sec": duration_sec,
            "timestamp": timestamp
        })

    return artifacts, warnings

def normalize_chats_csv(csv_text: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Normalize instant messaging and chat logs CSV export.
    Returns: (list_of_chat_artifacts, list_of_warnings)
    """
    artifacts = []
    warnings = []
    rows = _parse_csv_rows(csv_text)

    for idx, row in enumerate(rows, start=1):
        sender = _get_val(row, ["sender", "sender_id", "from", "source", "author"])
        receiver = _get_val(row, ["receiver", "receiver_id", "to", "target", "recipient"])
        platform = _get_val(row, ["platform", "app", "channel", "network"], "Chat")
        timestamp = _get_val(row, ["timestamp", "time", "date_time", "datetime", "sent_at"])
        message = _get_val(row, ["message", "text", "message_text", "body", "content"])
        record_id = _get_val(row, ["record_id", "id", "chat_id", "msg_id"]) or f"CHAT-{uuid.uuid4().hex[:6].upper()}"

        if not sender or not receiver:
            warnings.append(f"Row {idx} in chats.csv missing sender or receiver ({row})")
            continue

        artifacts.append({
            "record_type": "chat",
            "record_id": record_id,
            "sender_id": sender,
            "receiver_id": receiver,
            "platform": platform,
            "timestamp": timestamp,
            "message": message
        })

    return artifacts, warnings

def normalize_files_csv(csv_text: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Normalize file transfer and digital evidence file logs CSV export.
    Returns: (list_of_file_artifacts, list_of_warnings)
    """
    artifacts = []
    warnings = []
    rows = _parse_csv_rows(csv_text)

    for idx, row in enumerate(rows, start=1):
        owner = _get_val(row, ["owner", "owner_id", "sender", "from", "user", "source"])
        transferred_to = _get_val(row, ["transferred_to", "transferred_to_id", "receiver", "to", "recipient"])
        filename = _get_val(row, ["filename", "file_name", "name", "path"], "evidence_file.bin")
        hash_sha256 = _get_val(row, ["hash_sha256", "sha256", "file_hash", "hash", "checksum"], "0" * 64)
        timestamp = _get_val(row, ["timestamp", "time", "date_time", "datetime", "transferred_at"])
        record_id = _get_val(row, ["record_id", "id", "file_id"]) or f"FILE-{uuid.uuid4().hex[:6].upper()}"

        if not owner:
            warnings.append(f"Row {idx} in files.csv missing owner identifier ({row})")
            continue

        artifacts.append({
            "record_type": "file_artifact",
            "record_id": record_id,
            "owner_id": owner,
            "transferred_to_id": transferred_to or None,
            "filename": filename,
            "hash_sha256": hash_sha256,
            "timestamp": timestamp
        })

    return artifacts, warnings

def _haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate great-circle distance between two GPS points in kilometers."""
    R = 6371.0 # Earth radius in km
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2)**2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c

def normalize_locations_csv(
    csv_text: str,
    co_location_threshold_km: float = 0.5,
    time_window_sec: int = 1800
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    """
    Normalize GPS / location pings and compute co-location interaction edges.
    Returns: (location_ping_artifacts, co_located_artifacts, list_of_warnings)
    """
    location_pings = []
    co_located = []
    warnings = []
    rows = _parse_csv_rows(csv_text)

    parsed_pings = []

    for idx, row in enumerate(rows, start=1):
        entity_id = _get_val(row, ["entity_id", "person_name", "user", "device_owner", "name"])
        lat = _get_float(row, ["lat", "latitude", "latitude_deg"])
        lng = _get_float(row, ["lng", "lon", "longitude", "longitude_deg"])
        timestamp = _get_val(row, ["timestamp", "time", "date_time", "datetime", "ping_time"])
        record_id = _get_val(row, ["record_id", "id", "ping_id"]) or f"LOC-{uuid.uuid4().hex[:6].upper()}"

        if not entity_id or (lat == 0.0 and lng == 0.0):
            warnings.append(f"Row {idx} in locations.csv missing valid entity or GPS coordinates ({row})")
            continue

        item = {
            "record_type": "location_ping",
            "record_id": record_id,
            "entity_id": entity_id,
            "lat": lat,
            "lng": lng,
            "timestamp": timestamp
        }
        location_pings.append(item)
        parsed_pings.append(item)

    # Compute pairwise co-locations
    for i in range(len(parsed_pings)):
        for j in range(i + 1, len(parsed_pings)):
            p1 = parsed_pings[i]
            p2 = parsed_pings[j]
            if p1["entity_id"] == p2["entity_id"]:
                continue

            dist_km = _haversine_distance_km(p1["lat"], p1["lng"], p2["lat"], p2["lng"])
            if dist_km <= co_location_threshold_km:
                co_located.append({
                    "record_type": "co_located",
                    "record_id": f"COLOC-{uuid.uuid4().hex[:6].upper()}",
                    "entity1": p1["entity_id"],
                    "entity2": p2["entity_id"],
                    "distance_km": round(dist_km, 3),
                    "timestamp": p1["timestamp"] or p2["timestamp"]
                })

    return location_pings, co_located, warnings

def normalize_browser_history_csv(csv_text: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Normalize browser search and navigation history CSV export.
    Returns: (list_of_browser_artifacts, list_of_warnings)
    """
    artifacts = []
    warnings = []
    rows = _parse_csv_rows(csv_text)

    for idx, row in enumerate(rows, start=1):
        entity_id = _get_val(row, ["entity_id", "user", "device_owner", "person_name", "name"])
        url = _get_val(row, ["url", "domain", "site", "link", "visited_url"])
        timestamp = _get_val(row, ["timestamp", "time", "date_time", "datetime", "visited_at"])
        record_id = _get_val(row, ["record_id", "id", "nav_id"]) or f"BROWSE-{uuid.uuid4().hex[:6].upper()}"

        if not entity_id or not url:
            warnings.append(f"Row {idx} in browser_history.csv missing entity or URL ({row})")
            continue

        artifacts.append({
            "record_type": "browser_history",
            "record_id": record_id,
            "entity_id": entity_id,
            "url": url,
            "timestamp": timestamp
        })

    return artifacts, warnings

def normalize_entities_csv(csv_text: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Normalize suspect and entity profiles CSV export.
    Returns: (list_of_entity_dicts, list_of_warnings)
    """
    entities = []
    warnings = []
    rows = _parse_csv_rows(csv_text)

    for idx, row in enumerate(rows, start=1):
        entity_id = _get_val(row, ["entity_id", "id", "person_id", "name", "full_name"])
        name = _get_val(row, ["name", "full_name", "person_name", "alias"], entity_id)
        phone = _get_val(row, ["phone", "mobile", "number", "phone_number", "contact"])
        device_id = _get_val(row, ["device_id", "imei", "mac", "device", "hardware_id"])
        ip = _get_val(row, ["ip", "ip_address", "network_ip", "host"])

        if not entity_id:
            warnings.append(f"Row {idx} in entities.csv missing entity_id ({row})")
            continue

        entities.append({
            "entity_id": entity_id,
            "name": name,
            "phone": phone,
            "device_id": device_id,
            "ip": ip
        })

    return entities, warnings
