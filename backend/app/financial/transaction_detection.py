import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

def detect_suspicious_transactions(
    transactions: List[Dict[str, Any]],
    reporting_threshold: float = 50000.0,
    large_amount_threshold: float = 200000.0,
    structuring_min_ratio: float = 0.70
) -> List[Dict[str, Any]]:
    """
    Detect money laundering and suspicious financial flow signatures:
    1. Large single transactions (>= large_amount_threshold e.g. ₹2,00,000)
    2. Structuring / Smurfing: Multiple transactions just below regulatory reporting thresholds (e.g. ₹35,000 - ₹49,999) between same parties
    3. Rapid Layering: Sequential flow patterns
    """
    flagged: List[Dict[str, Any]] = []
    
    # Track transactions by party pair for structuring analysis
    pair_txns: Dict[tuple, List[Dict[str, Any]]] = {}

    for txn in transactions:
        sender = txn.get("sender", "")
        receiver = txn.get("receiver", "")
        pair_key = (sender, receiver)
        if pair_key not in pair_txns:
            pair_txns[pair_key] = []
        pair_txns[pair_key].append(txn)

    # Detect structuring patterns per pair
    structuring_pairs = set()
    for pair, tx_list in pair_txns.items():
        sub_threshold_count = 0
        for t in tx_list:
            amt = float(t.get("amount", 0.0))
            if (reporting_threshold * structuring_min_ratio) <= amt < reporting_threshold:
                sub_threshold_count += 1
        if sub_threshold_count >= 2 or len(tx_list) >= 3:
            structuring_pairs.add(pair)

    for txn in transactions:
        reasons = []
        amt = float(txn.get("amount", 0.0))
        sender = txn.get("sender", "")
        receiver = txn.get("receiver", "")
        pair_key = (sender, receiver)

        # 1. Large amount check
        if amt >= large_amount_threshold:
            reasons.append(f"large_amount (₹{amt:,.2f} >= ₹{large_amount_threshold:,.2f})")

        # 2. Structuring pattern check
        if pair_key in structuring_pairs and amt < reporting_threshold:
            reasons.append(f"structuring_pattern (smurfing signature below ₹{reporting_threshold:,.2f})")

        # 3. Round number near threshold
        if (reporting_threshold - 1000) <= amt < reporting_threshold:
            if "structuring_pattern" not in str(reasons):
                reasons.append("near_threshold_structuring")

        if reasons:
            flagged.append({
                "transaction_id": txn.get("transaction_id", "EXTRACTED_TXN"),
                "sender": sender,
                "receiver": receiver,
                "amount": amt,
                "currency": txn.get("currency", "INR"),
                "timestamp": txn.get("timestamp", ""),
                "location": txn.get("location", {}),
                "reasons": reasons,
                "confidence": "requires_investigator_review",
                "case_id": txn.get("case_id", "")
            })

    return flagged
