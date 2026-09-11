import re
import logging
from typing import Dict, List, Any, Optional
from app.nlp.entity_extractor import get_spacy_model, extract_entities, PHONE_REGEX

logger = logging.getLogger(__name__)

# Trigger keyword lexicons for investigative event classification
CALL_TRIGGERS = [
    "called", "phoned", "spoke to", "contacted over phone", "rang up",
    "dialed", "conversed with", "had a call with", "voice call"
]
TRANSACTION_TRIGGERS = [
    "transferred", "paid", "sent money", "deposited", "withdrew", "wired",
    "handed over cash", "remitted", "funds transferred", "transferred funds",
    "received payment", "transferred an amount"
]
MEETING_TRIGGERS = [
    "met", "meeting with", "gathered at", "seen with", "spotted with",
    "visited", "rendezvous", "assembled at", "conferred with"
]
COMMUNICATION_TRIGGERS = [
    "contacted", "messaged", "texted", "emailed", "chatted with",
    "communicated with", "sent message", "reached out to", "interacted with"
]
LOCATION_PRESENCE_TRIGGERS = [
    "seen near", "spotted at", "arrived at", "fled to", "staying at",
    "located at", "raided at", "present at", "intercepted at", "parked at",
    "lives in", "works in", "residing at"
]

DURATION_REGEX = re.compile(r"\b(\d+)\s*(minute|min|second|sec|hour|hr)s?\b", re.IGNORECASE)
AMOUNT_PARSE_REGEX = re.compile(r"[\d,]+(?:\.\d+)?")

def parse_duration_seconds(sentence_text: str) -> int:
    """Parse duration string from sentence and convert to seconds."""
    match = DURATION_REGEX.search(sentence_text)
    if not match:
        return 0
    val = int(match.group(1))
    unit = match.group(2).lower()
    if unit in ("hour", "hr"):
        return val * 3600
    elif unit in ("minute", "min"):
        return val * 60
    return val

def parse_numeric_amount(amount_text: str) -> float:
    """Extract numeric float from money string (e.g. '₹50,000' -> 50000.0)."""
    match = AMOUNT_PARSE_REGEX.search(amount_text)
    if not match:
        return 0.0
    clean_num = match.group(0).replace(",", "")
    try:
        return float(clean_num)
    except ValueError:
        return 0.0

def _find_entity_before_and_after_trigger(
    sentence_lower: str,
    trigger: str,
    entities_list: List[str]
) -> tuple[Optional[str], Optional[str]]:
    """
    Syntactically partition entities before (subject-like) and after (object-like) the trigger phrase.
    """
    trigger_pos = sentence_lower.find(trigger)
    if trigger_pos == -1 or not entities_list:
        return (entities_list[0] if entities_list else None,
                entities_list[1] if len(entities_list) > 1 else None)

    before = []
    after = []
    for ent in entities_list:
        ent_pos = sentence_lower.find(ent.lower())
        if ent_pos != -1:
            if ent_pos < trigger_pos:
                before.append((ent_pos, ent))
            else:
                after.append((ent_pos, ent))

    # Sort by proximity to trigger
    before.sort(key=lambda x: x[0], reverse=True) # closest before
    after.sort(key=lambda x: x[0])                 # closest after

    subj = before[0][1] if before else (entities_list[0] if entities_list else None)
    obj = after[0][1] if after else (entities_list[1] if len(entities_list) > 1 and entities_list[1] != subj else None)

    return subj, obj

def extract_events_from_text(text: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    Extract structured crime investigation events from raw unstructured narrative/FIR text:
    - calls: Voice calls and direct phone conversations
    - transactions: Monetary and fund transfers
    - meetings: Physical meetings, rendezvous, co-presence
    - communications: General contacts, messages, electronic chats
    - location_presence: Suspect location sightings and movements
    """
    if not text or not text.strip():
        return {
            "calls": [],
            "transactions": [],
            "meetings": [],
            "communications": [],
            "location_presence": []
        }

    nlp = get_spacy_model()
    doc = nlp(text)

    calls: List[Dict[str, Any]] = []
    transactions: List[Dict[str, Any]] = []
    meetings: List[Dict[str, Any]] = []
    communications: List[Dict[str, Any]] = []
    location_presence: List[Dict[str, Any]] = []

    for sent in doc.sents:
        sent_text = sent.text.strip()
        if not sent_text:
            continue
        sent_lower = sent_text.lower()

        # Extract entities specifically within this individual sentence
        sent_ents = extract_entities(sent_text)
        persons = sent_ents.get("PERSON", [])
        phones = sent_ents.get("PHONE", [])
        locations = sent_ents.get("LOCATION", [])
        orgs = sent_ents.get("ORGANIZATION", [])
        money_ents = sent_ents.get("MONEY", [])
        dates = sent_ents.get("DATE", [])
        times = sent_ents.get("TIME", [])

        # Build composite timestamp string
        date_str = dates[0] if dates else ""
        time_str = times[0] if times else ""
        timestamp_str = f"{date_str} {time_str}".strip() or "Unspecified Date/Time"

        # 1. CALL EVENT DETECTION
        is_call = False
        for trigger in CALL_TRIGGERS:
            if trigger in sent_lower:
                caller, callee = _find_entity_before_and_after_trigger(sent_lower, trigger, persons)
                caller = caller or "Unknown Caller"
                if not callee:
                    callee = phones[0] if phones else "Unknown Callee"

                duration_sec = parse_duration_seconds(sent_text)

                calls.append({
                    "event_type": "CALL",
                    "caller": caller,
                    "callee": callee,
                    "duration_sec": duration_sec,
                    "timestamp": timestamp_str,
                    "source_sentence": sent_text,
                    "confidence": 0.90 if caller != "Unknown Caller" and callee != "Unknown Callee" else 0.75
                })
                is_call = True
                break

        # 2. TRANSACTION EVENT DETECTION
        for trigger in TRANSACTION_TRIGGERS:
            if trigger in sent_lower:
                sender, receiver = _find_entity_before_and_after_trigger(sent_lower, trigger, persons)
                sender = sender or (persons[0] if persons else "Unknown Sender")
                receiver = receiver or (persons[1] if len(persons) > 1 else "Unknown Receiver")

                # Amount extraction
                amount_val = 0.0
                currency = "INR"
                if money_ents:
                    amount_val = parse_numeric_amount(money_ents[0])
                else:
                    curr_match = re.search(r"(?:₹|Rs\.?|INR|\$)\s*([\d,]+)", sent_text, re.IGNORECASE)
                    if curr_match:
                        amount_val = parse_numeric_amount(curr_match.group(1))

                landmark = orgs[0] if orgs else (locations[0] if locations else "Unspecified Branch")
                area = locations[0] if locations else (orgs[0] if orgs else "Unspecified Area")

                transactions.append({
                    "event_type": "TRANSACTION",
                    "sender": sender,
                    "receiver": receiver,
                    "amount": amount_val,
                    "currency": currency,
                    "timestamp": timestamp_str,
                    "location": {
                        "landmark": landmark,
                        "area": area
                    },
                    "source_sentence": sent_text,
                    "confidence": 0.88 if amount_val > 0 else 0.72
                })
                break

        # 3. MEETING EVENT DETECTION
        for trigger in MEETING_TRIGGERS:
            if trigger in sent_lower:
                subj, obj = _find_entity_before_and_after_trigger(sent_lower, trigger, persons)
                participants = [p for p in [subj, obj] if p] or persons
                if not participants and persons:
                    participants = persons
                venue = locations[0] if locations else (orgs[0] if orgs else "Unspecified Location")

                meetings.append({
                    "event_type": "MEETING",
                    "participants": participants,
                    "location": venue,
                    "timestamp": timestamp_str,
                    "source_sentence": sent_text,
                    "confidence": 0.85 if len(participants) >= 2 else 0.70
                })
                break

        # 4. GENERAL COMMUNICATION DETECTION (if not already captured as call)
        if not is_call:
            for trigger in COMMUNICATION_TRIGGERS:
                if trigger in sent_lower:
                    sender, receiver = _find_entity_before_and_after_trigger(sent_lower, trigger, persons)
                    sender = sender or (persons[0] if persons else "Unknown Sender")
                    receiver = receiver or (persons[1] if len(persons) > 1 else (phones[0] if phones else "Unknown Receiver"))

                    # Identify communication medium
                    medium = "mobile_phone" if "phone" in sent_lower or phones else (
                        "email" if "email" in sent_lower else ("chat" if "chat" in sent_lower or "message" in sent_lower else "unspecified_channel")
                    )

                    communications.append({
                        "event_type": "COMMUNICATION",
                        "sender": sender,
                        "receiver": receiver,
                        "medium": medium,
                        "timestamp": timestamp_str,
                        "source_sentence": sent_text,
                        "confidence": 0.85 if sender != "Unknown Sender" else 0.70
                    })
                    break

        # 5. LOCATION PRESENCE DETECTION
        for trigger in LOCATION_PRESENCE_TRIGGERS:
            if trigger in sent_lower and locations:
                target_person = persons[0] if persons else "Unknown Subject"
                target_location = locations[0]

                location_presence.append({
                    "event_type": "LOCATION_PRESENCE",
                    "person": target_person,
                    "location": target_location,
                    "timestamp": timestamp_str,
                    "source_sentence": sent_text,
                    "confidence": 0.85
                })
                break

    return {
        "calls": calls,
        "transactions": transactions,
        "meetings": meetings,
        "communications": communications,
        "location_presence": location_presence
    }
