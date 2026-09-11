from typing import Dict, Any
from sqlalchemy.orm import Session
from app.models import TransactionRecord, Alert

def analyze_case_transactions(db: Session, case_id: str) -> Dict[str, Any]:
    """
    Compute financial intelligence rollup and transaction timeline for a case.
    """
    transactions = db.query(TransactionRecord).filter(TransactionRecord.case_id == case_id).all()
    if not transactions:
        return {
            "case_id": case_id,
            "total_transactions": 0,
            "total_amount_moved": 0.0,
            "largest_transaction": None,
            "structuring_flags_pending_review": 0,
            "transaction_timeline": [],
            "disclaimer": "Financial patterns reflect recorded transaction values and locations."
        }

    total_amount = sum(t.amount for t in transactions)
    largest = max(transactions, key=lambda t: t.amount)

    pending_structuring = db.query(Alert).filter(
        Alert.case_id == case_id,
        Alert.alert_type == "TRANSACTION_PATTERN",
        Alert.status == "PENDING"
    ).count()

    timeline = []
    for t in sorted(transactions, key=lambda x: str(x.timestamp or "")):
        timeline.append({
            "transaction_id": t.transaction_id,
            "timestamp": t.timestamp,
            "sender": t.sender,
            "receiver": t.receiver,
            "amount": t.amount,
            "currency": t.currency,
            "location": {
                "landmark": t.landmark,
                "area": t.area
            }
        })

    return {
        "case_id": case_id,
        "total_transactions": len(transactions),
        "total_amount_moved": round(total_amount, 2),
        "largest_transaction": {
            "transaction_id": largest.transaction_id,
            "sender": largest.sender,
            "receiver": largest.receiver,
            "amount": largest.amount,
            "location": {
                "landmark": largest.landmark,
                "area": largest.area
            },
            "timestamp": largest.timestamp
        } if largest else None,
        "structuring_flags_pending_review": pending_structuring,
        "transaction_timeline": timeline,
        "disclaimer": "Financial patterns reflect recorded transaction values and locations."
    }
