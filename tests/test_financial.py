import pytest
from app.financial.transaction_detection import detect_suspicious_transactions

def test_suspicious_transaction_structuring():
    txns = [
        {"transaction_id": "T1", "sender": "A", "receiver": "B", "amount": 49000, "timestamp": "2026-01-01T10:00:00"},
        {"transaction_id": "T2", "sender": "A", "receiver": "B", "amount": 48000, "timestamp": "2026-01-01T10:20:00"},
        {"transaction_id": "T3", "sender": "A", "receiver": "B", "amount": 47000, "timestamp": "2026-01-01T10:40:00"},
    ]
    flagged = detect_suspicious_transactions(txns, reporting_threshold=50000.0)
    assert len(flagged) == 3
    assert any("structuring" in r for r in flagged[0]["reasons"])

def test_large_amount_transaction_detection():
    txns = [
        {"transaction_id": "T10", "sender": "Alpha", "receiver": "Beta", "amount": 500000.0, "timestamp": "2026-01-02T14:00:00"}
    ]
    flagged = detect_suspicious_transactions(txns, large_amount_threshold=200000.0)
    assert len(flagged) == 1
    assert any("large_amount" in r for r in flagged[0]["reasons"])
