import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from app import create_app


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def small_case():
    """A minimal, hand-built case for deterministic unit tests."""
    return {
        "case_id": "TEST-CASE",
        "note": "unit test fixture",
        "entities": [
            {"entity_id": "A", "name": "Alice", "phone": "111", "device_id": "DA", "ip": "1.1.1.1"},
            {"entity_id": "B", "name": "Bob", "phone": "222", "device_id": "DB", "ip": "1.1.1.2"},
            {"entity_id": "C", "name": "Carol", "phone": "333", "device_id": "DC", "ip": "1.1.1.3"},
            {"entity_id": "D", "name": "Dave", "phone": "444", "device_id": "DD", "ip": "1.1.1.4"},
        ],
        "artifacts": [
            {"record_type": "call", "record_id": "r1", "caller_id": "A", "callee_id": "B",
             "duration_sec": 60, "timestamp": "2026-01-01T10:00:00"},
            {"record_type": "call", "record_id": "r2", "caller_id": "B", "callee_id": "C",
             "duration_sec": 30, "timestamp": "2026-01-01T11:00:00"},
            {"record_type": "chat", "record_id": "r3", "sender_id": "A", "receiver_id": "C",
             "platform": "TestChat", "timestamp": "2026-01-01T12:00:00"},
            {"record_type": "file_artifact", "record_id": "r4", "owner_id": "A", "device_id": "DA",
             "filename": "doc.dat", "hash_sha256": "abc123", "timestamp": "2026-01-01T13:00:00",
             "transferred_to_id": "B"},
            {"record_type": "browser_history", "record_id": "r5", "entity_id": "D", "device_id": "DD",
             "url": "https://example.test/x", "timestamp": "2026-01-01T14:00:00"},
            # D is isolated (no edges) — useful for testing disconnected-node behavior
        ],
    }
