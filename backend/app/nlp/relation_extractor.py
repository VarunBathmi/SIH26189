import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

def extract_relationships(
    entities: Dict[str, List[str]],
    events: Dict[str, List[Dict[str, Any]]],
    case_id: str,
    document_id: str
) -> List[Dict[str, Any]]:
    """
    Extract graph relationships from extracted entities and events:
    - MENTIONED_WITH (Person <-> Person)
    - LOCATED_AT (Person <-> Location)
    - AFFILIATED_WITH (Person <-> Organization)
    - CALLED (Caller -> Callee)
    - TRANSACTED_WITH (Sender -> Receiver)
    - MENTIONED_IN (Entity -> Case)
    """
    relationships: List[Dict[str, Any]] = []
    seen_pairs = set()

    persons = entities.get("PERSON", [])
    locations = entities.get("LOCATION", [])
    organizations = entities.get("ORGANIZATION", [])

    # 1. Person <-> Person (MENTIONED_WITH)
    for i in range(len(persons)):
        for j in range(i + 1, len(persons)):
            p1, p2 = sorted([persons[i], persons[j]])
            pair_key = ("MENTIONED_WITH", p1, p2)
            if pair_key not in seen_pairs:
                seen_pairs.add(pair_key)
                relationships.append({
                    "type": "MENTIONED_WITH",
                    "source": p1,
                    "target": p2,
                    "source_type": "Person",
                    "target_type": "Person",
                    "properties": {
                        "case_id": case_id,
                        "source_document": document_id
                    }
                })

    # 2. Person <-> Location (LOCATED_AT)
    for person in persons:
        for loc in locations:
            pair_key = ("LOCATED_AT", person, loc)
            if pair_key not in seen_pairs:
                seen_pairs.add(pair_key)
                relationships.append({
                    "type": "LOCATED_AT",
                    "source": person,
                    "target": loc,
                    "source_type": "Person",
                    "target_type": "Location",
                    "properties": {
                        "case_id": case_id,
                        "source_document": document_id
                    }
                })

    # 3. Person <-> Organization (AFFILIATED_WITH)
    for person in persons:
        for org in organizations:
            pair_key = ("AFFILIATED_WITH", person, org)
            if pair_key not in seen_pairs:
                seen_pairs.add(pair_key)
                relationships.append({
                    "type": "AFFILIATED_WITH",
                    "source": person,
                    "target": org,
                    "source_type": "Person",
                    "target_type": "Organization",
                    "properties": {
                        "case_id": case_id,
                        "source_document": document_id
                    }
                })

    # 4. Call Events (CALLED)
    for call in events.get("calls", []):
        caller = call.get("caller")
        callee = call.get("callee")
        if caller and callee and caller != "Unknown Person":
            relationships.append({
                "type": "CALLED",
                "source": caller,
                "target": callee,
                "source_type": "Person",
                "target_type": "Person" if not callee.isdigit() else "Phone",
                "properties": {
                    "case_id": case_id,
                    "duration_sec": call.get("duration_sec", 0),
                    "timestamp": call.get("timestamp", ""),
                    "source_document": document_id
                }
            })

    # 5. Transaction Events (TRANSACTED_WITH)
    for txn in events.get("transactions", []):
        sender = txn.get("sender")
        receiver = txn.get("receiver")
        if sender and receiver and sender != "Unknown Sender":
            relationships.append({
                "type": "TRANSACTED_WITH",
                "source": sender,
                "target": receiver,
                "source_type": "Person",
                "target_type": "Person",
                "properties": {
                    "case_id": case_id,
                    "amount": txn.get("amount", 0.0),
                    "currency": txn.get("currency", "INR"),
                    "timestamp": txn.get("timestamp", ""),
                    "source_document": document_id
                }
            })

    # 6. Entity MENTIONED_IN Case
    for person in persons:
        relationships.append({
            "type": "MENTIONED_IN",
            "source": person,
            "target": case_id,
            "source_type": "Person",
            "target_type": "Case",
            "properties": {"source_document": document_id}
        })
    for loc in locations:
        relationships.append({
            "type": "MENTIONED_IN",
            "source": loc,
            "target": case_id,
            "source_type": "Location",
            "target_type": "Case",
            "properties": {"source_document": document_id}
        })

    return relationships
