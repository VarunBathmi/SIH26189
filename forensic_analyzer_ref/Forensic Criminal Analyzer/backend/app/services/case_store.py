"""
Simple in-memory case store. Each 'case' is a loaded forensic dataset with
its own ForensicGraphEngine instance. Good enough for a demo/testing tool;
swap for a real DB (Postgres, etc.) for production use.
"""
import json
import os
import uuid
from datetime import datetime

from app.services.graph_engine import ForensicGraphEngine

_CASES = {}          # case_id -> {"engine": ForensicGraphEngine, "meta": {...}, "log": [...]}
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")


def _log_action(case_id, action, details=None):
    """Chain-of-custody style audit log — every analytical action is timestamped."""
    entry = {
        "log_id": str(uuid.uuid4()),
        "timestamp": datetime.now().isoformat(),
        "action": action,
        "details": details or {},
    }
    _CASES[case_id]["log"].append(entry)
    return entry


def load_case_from_dict(case_data: dict):
    case_id = case_data.get("case_id", str(uuid.uuid4()))
    engine = ForensicGraphEngine(case_data)
    _CASES[case_id] = {
        "engine": engine,
        "meta": {
            "case_id": case_id,
            "loaded_at": datetime.now().isoformat(),
            "entity_count": len(engine.entities),
            "artifact_count": len(case_data.get("artifacts", [])),
            "note": case_data.get("note", ""),
        },
        "log": [],
    }
    _log_action(case_id, "case_loaded", {"entity_count": len(engine.entities)})
    return case_id


def load_demo_case():
    path = os.path.join(DATA_DIR, "synthetic_case_demo001.json")
    with open(path) as f:
        case_data = json.load(f)
    return load_case_from_dict(case_data)


def list_cases():
    return [c["meta"] for c in _CASES.values()]


def get_engine(case_id) -> ForensicGraphEngine:
    if case_id not in _CASES:
        return None
    return _CASES[case_id]["engine"]


def get_log(case_id):
    if case_id not in _CASES:
        return None
    return _CASES[case_id]["log"]


def log_action(case_id, action, details=None):
    if case_id in _CASES:
        return _log_action(case_id, action, details)
    return None
