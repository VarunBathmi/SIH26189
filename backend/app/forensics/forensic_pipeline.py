import os
import json
import csv
import logging
from pathlib import Path
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

def parse_forensic_artifact(file_path: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    Parse a forensic evidence artifact (JSON or CSV) and extract normalized:
    - calls
    - messages
    - devices
    - files
    - locations
    """
    path = Path(file_path)
    if not path.exists():
        return {}

    suffix = path.suffix.lower()
    raw_data: List[Dict[str, Any]] = []

    try:
        if suffix == ".json":
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                loaded = json.load(f)
                if isinstance(loaded, list):
                    raw_data = loaded
                elif isinstance(loaded, dict):
                    # Check if items are nested
                    for k in ("records", "calls", "messages", "items", "data"):
                        if k in loaded and isinstance(loaded[k], list):
                            raw_data = loaded[k]
                            break
                    if not raw_data:
                        raw_data = [loaded]
        elif suffix in (".csv", ".tsv"):
            delimiter = "\t" if suffix == ".tsv" else ","
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f, delimiter=delimiter)
                raw_data = list(reader)
    except Exception as e:
        logger.warning(f"Could not parse forensic file {file_path}: {e}")
        return {}

    calls = []
    messages = []
    devices = []
    files = []
    locations = []

    for item in raw_data:
        # Check calls
        if any(k in item for k in ("caller", "callee", "call_duration", "duration_sec", "dialed_number")):
            calls.append({
                "caller": item.get("caller") or item.get("from") or item.get("source", "Unknown"),
                "callee": item.get("callee") or item.get("to") or item.get("target") or item.get("dialed_number", "Unknown"),
                "duration_sec": int(item.get("duration_sec") or item.get("call_duration") or item.get("duration") or 0),
                "timestamp": item.get("timestamp") or item.get("date_time") or item.get("time", ""),
                "case_id": item.get("case_id", "")
            })
        # Check messages / chats
        elif any(k in item for k in ("message_text", "body", "sms_body", "chat_message", "platform")):
            messages.append({
                "sender": item.get("sender") or item.get("from", "Unknown"),
                "receiver": item.get("receiver") or item.get("to", "Unknown"),
                "platform": item.get("platform") or item.get("app", "SMS"),
                "message_text": item.get("message_text") or item.get("body") or item.get("text", ""),
                "timestamp": item.get("timestamp") or item.get("date_time", "")
            })
        # Check GPS / Locations
        elif any(k in item for k in ("latitude", "lat", "longitude", "lng", "lon")):
            try:
                lat = float(item.get("latitude") or item.get("lat"))
                lon = float(item.get("longitude") or item.get("lng") or item.get("lon"))
                locations.append({
                    "person_name": item.get("person_name") or item.get("user") or item.get("device_owner", "Unknown"),
                    "latitude": lat,
                    "longitude": lon,
                    "timestamp": item.get("timestamp") or item.get("date_time", ""),
                    "location_name": item.get("location_name") or item.get("address", "")
                })
            except (ValueError, TypeError):
                pass
        # Check Devices
        elif any(k in item for k in ("imei", "mac_address", "device_model", "serial_number")):
            devices.append({
                "owner_name": item.get("owner_name") or item.get("user", "Unknown"),
                "device_model": item.get("device_model") or item.get("model", "Unknown Device"),
                "imei": item.get("imei", ""),
                "mac_address": item.get("mac_address", ""),
                "os_version": item.get("os_version", "")
            })
        # Check Files
        elif any(k in item for k in ("file_hash", "checksum", "file_name", "transferred_file")):
            files.append({
                "filename": item.get("filename") or item.get("file_name", "evidence_file"),
                "file_hash": item.get("file_hash") or item.get("hash") or item.get("sha256", ""),
                "sender": item.get("sender") or item.get("from", "Unknown"),
                "receiver": item.get("receiver") or item.get("to", "Unknown"),
                "timestamp": item.get("timestamp", "")
            })

    return {
        "calls": calls,
        "messages": messages,
        "devices": devices,
        "files": files,
        "locations": locations
    }
