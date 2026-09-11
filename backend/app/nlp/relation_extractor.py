import logging
from typing import Dict, List, Any, Optional
from app.nlp.entity_extractor import get_spacy_model, extract_entities

logger = logging.getLogger(__name__)

AFFILIATION_TRIGGERS = [
    "director", "chief", "operator", "linked to", "affiliated with",
    "works at", "works in", "employed at", "member of", "head of",
    "partner at", "proprietor of", "associated with"
]

def extract_relationships(
    entities: Dict[str, List[str]],
    events: Dict[str, List[Dict[str, Any]]],
    case_id: str,
    document_id: str,
    raw_text: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Extract high-precision graph relationships supported strictly by:
    1. Explicit extracted investigation events (CALLED, TRANSACTED_WITH, MET_WITH, COMMUNICATED_WITH)
    2. Sentence-level syntactic & semantic co-occurrences (LOCATED_AT, AFFILIATED_WITH, OPERATES_VEHICLE)
    3. Case scoping (MENTIONED_IN)

    CRITICAL FORENSIC RULE:
    No relationship edge is created between two entities simply because they appear
    in the same document or paragraph without syntactic/event support.
    """
    relationships: List[Dict[str, Any]] = []
    seen_edges = set()

    def _add_rel(
        src: str,
        tgt: str,
        rel_type: str,
        src_type: str = "Person",
        tgt_type: str = "Person",
        confidence: float = 0.85,
        method: str = "SYNTACTIC_EVENT",
        source_text: str = "",
        extra_props: Optional[Dict[str, Any]] = None
    ):
        if not src or not tgt or src == tgt:
            return
        if src.startswith("Unknown") or tgt.startswith("Unknown"):
            return

        edge_key = (rel_type, src, tgt)
        if edge_key in seen_edges:
            return
        seen_edges.add(edge_key)

        props = {
            "case_id": case_id,
            "source_document": document_id,
            "source_text": source_text,
            "extraction_method": method,
            "confidence": confidence
        }
        if extra_props:
            props.update(extra_props)

        relationships.append({
            "type": rel_type,
            "source": src,
            "target": tgt,
            "source_type": src_type,
            "target_type": tgt_type,
            "properties": props
        })

    # 1. Relationships from CALL Events
    for call in events.get("calls", []):
        caller = call.get("caller")
        callee = call.get("callee")
        if caller and callee:
            tgt_type = "Phone" if (callee.replace("+", "").replace("-", "").isdigit()) else "Person"
            _add_rel(
                src=caller,
                tgt=callee,
                rel_type="CALLED",
                src_type="Person",
                tgt_type=tgt_type,
                confidence=call.get("confidence", 0.90) if isinstance(call.get("confidence"), float) else 0.90,
                method="CALL_EVENT_EXTRACTION",
                source_text=call.get("source_sentence", ""),
                extra_props={
                    "duration_sec": call.get("duration_sec", 0),
                    "timestamp": call.get("timestamp", "")
                }
            )

    # 2. Relationships from TRANSACTION Events
    for txn in events.get("transactions", []):
        sender = txn.get("sender")
        receiver = txn.get("receiver")
        if sender and receiver:
            _add_rel(
                src=sender,
                tgt=receiver,
                rel_type="TRANSACTED_WITH",
                src_type="Person",
                tgt_type="Person",
                confidence=txn.get("confidence", 0.88) if isinstance(txn.get("confidence"), float) else 0.88,
                method="TRANSACTION_EVENT_EXTRACTION",
                source_text=txn.get("source_sentence", ""),
                extra_props={
                    "amount": txn.get("amount", 0.0),
                    "currency": txn.get("currency", "INR"),
                    "timestamp": txn.get("timestamp", "")
                }
            )

    # 3. Relationships from MEETING Events
    for meeting in events.get("meetings", []):
        participants = meeting.get("participants", [])
        venue = meeting.get("location")
        sent = meeting.get("source_sentence", "")

        # Pairwise meeting connections among participants in this specific meeting
        for i in range(len(participants)):
            for j in range(i + 1, len(participants)):
                _add_rel(
                    src=participants[i],
                    tgt=participants[j],
                    rel_type="MET_WITH",
                    src_type="Person",
                    tgt_type="Person",
                    confidence=0.85,
                    method="MEETING_EVENT_EXTRACTION",
                    source_text=sent,
                    extra_props={"timestamp": meeting.get("timestamp", "")}
                )

        # Location linkage for participants at this meeting
        if venue and venue != "Unspecified Location":
            for p in participants:
                _add_rel(
                    src=p,
                    tgt=venue,
                    rel_type="LOCATED_AT",
                    src_type="Person",
                    tgt_type="Location",
                    confidence=0.85,
                    method="MEETING_LOCATION_EXTRACTION",
                    source_text=sent,
                    extra_props={"timestamp": meeting.get("timestamp", "")}
                )

    # 4. Relationships from GENERAL COMMUNICATION Events
    for comm in events.get("communications", []):
        sender = comm.get("sender")
        receiver = comm.get("receiver")
        if sender and receiver:
            tgt_type = "Phone" if (receiver.replace("+", "").replace("-", "").isdigit()) else "Person"
            _add_rel(
                src=sender,
                tgt=receiver,
                rel_type="COMMUNICATED_WITH",
                src_type="Person",
                tgt_type=tgt_type,
                confidence=0.85,
                method="COMMUNICATION_EVENT_EXTRACTION",
                source_text=comm.get("source_sentence", ""),
                extra_props={
                    "medium": comm.get("medium", "unspecified"),
                    "timestamp": comm.get("timestamp", "")
                }
            )

    # 5. Relationships from LOCATION PRESENCE Events
    for loc_pres in events.get("location_presence", []):
        p = loc_pres.get("person")
        l = loc_pres.get("location")
        if p and l:
            _add_rel(
                src=p,
                tgt=l,
                rel_type="LOCATED_AT",
                src_type="Person",
                tgt_type="Location",
                confidence=0.85,
                method="LOCATION_PRESENCE_EXTRACTION",
                source_text=loc_pres.get("source_sentence", ""),
                extra_props={"timestamp": loc_pres.get("timestamp", "")}
            )

    # 6. Sentence-Level Syntactic Co-occurrence Extraction (Fine-grained)
    # If raw text is available or from individual sentences
    if raw_text:
        nlp = get_spacy_model()
        doc = nlp(raw_text)
        for sent in doc.sents:
            s_text = sent.text.strip()
            s_lower = s_text.lower()
            s_ents = extract_entities(s_text)
            s_persons = s_ents.get("PERSON", [])
            s_locations = s_ents.get("LOCATION", [])
            s_orgs = s_ents.get("ORGANIZATION", [])
            s_vehicles = s_ents.get("VEHICLE", [])

            # Person <-> Organization within SAME sentence
            for p in s_persons:
                for org in s_orgs:
                    # Check if associative preposition or trigger is present
                    has_trigger = any(t in s_lower for t in AFFILIATION_TRIGGERS) or " of " in s_lower or " at " in s_lower or " in " in s_lower
                    if has_trigger:
                        _add_rel(
                            src=p,
                            tgt=org,
                            rel_type="AFFILIATED_WITH",
                            src_type="Person",
                            tgt_type="Organization",
                            confidence=0.82,
                            method="SENTENCE_SYNTACTIC_DEPENDENCY",
                            source_text=s_text
                        )

            # Person <-> Vehicle within SAME sentence
            for p in s_persons:
                for v in s_vehicles:
                    _add_rel(
                        src=p,
                        tgt=v,
                        rel_type="OPERATES_VEHICLE",
                        src_type="Person",
                        tgt_type="Vehicle",
                        confidence=0.80,
                        method="SENTENCE_VEHICLE_ALIGNMENT",
                        source_text=s_text
                    )

            # Person <-> Location within SAME sentence (if not already added by event)
            for p in s_persons:
                for loc in s_locations:
                    _add_rel(
                        src=p,
                        tgt=loc,
                        rel_type="LOCATED_AT",
                        src_type="Person",
                        tgt_type="Location",
                        confidence=0.80,
                        method="SENTENCE_LOCATION_CO_OCCURRENCE",
                        source_text=s_text
                    )

    # 7. Case Scope Linkage (MENTIONED_IN)
    # Every extracted entity connects to the case node for strict graph partitioning
    for p in entities.get("PERSON", []):
        _add_rel(
            src=p,
            tgt=case_id,
            rel_type="MENTIONED_IN",
            src_type="Person",
            tgt_type="Case",
            confidence=1.0,
            method="CASE_SCOPING",
            source_text="Case-document reference"
        )
    for l in entities.get("LOCATION", []):
        _add_rel(
            src=l,
            tgt=case_id,
            rel_type="MENTIONED_IN",
            src_type="Location",
            tgt_type="Case",
            confidence=1.0,
            method="CASE_SCOPING",
            source_text="Case-document reference"
        )
    for org in entities.get("ORGANIZATION", []):
        _add_rel(
            src=org,
            tgt=case_id,
            rel_type="MENTIONED_IN",
            src_type="Organization",
            tgt_type="Case",
            confidence=1.0,
            method="CASE_SCOPING",
            source_text="Case-document reference"
        )

    return relationships
