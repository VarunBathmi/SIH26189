import re
import logging
from typing import Dict, List, Any, Optional
from app.nlp.entity_extractor import get_spacy_model, extract_entities, PHONE_REGEX

logger = logging.getLogger(__name__)

CALL_TRIGGERS = ["called", "phoned", "spoke to", "contacted", "rang up", "dialed", "conversed with"]
TRANSACTION_TRIGGERS = ["transferred", "paid", "sent money", "deposited", "withdrew", "wired", "handed over"]

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

def extract_events_from_text(text: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    Extract structured CALL and TRANSACTION events from raw narrative report text
    using hybrid spaCy sentence segmentation, entity alignment, and trigger word slot-filling.
    """
    if not text:
        return {"calls": [], "transactions": []}

    nlp = get_spacy_model()
    doc = nlp(text)

    calls: List[Dict[str, Any]] = []
    transactions: List[Dict[str, Any]] = []

    for sent in doc.sents:
        sent_text = sent.text.strip()
        sent_lower = sent_text.lower()
        
        # Extract entities specifically within this sentence
        sent_ents = extract_entities(sent_text)
        persons = sent_ents.get("PERSON", [])
        phones = sent_ents.get("PHONE", [])
        locations = sent_ents.get("LOCATION", [])
        orgs = sent_ents.get("ORGANIZATION", [])
        money_ents = sent_ents.get("MONEY", [])
        dates = sent_ents.get("DATE", [])
        times = sent_ents.get("TIME", [])

        # Build approximate timestamp string from date and time
        date_str = dates[0] if dates else ""
        time_str = times[0] if times else ""
        timestamp_str = f"{date_str} {time_str}".strip() or "Unspecified Date/Time"

        # 1. CALL EVENT DETECTION
        for trigger in CALL_TRIGGERS:
            if trigger in sent_lower:
                trigger_idx = sent_lower.find(trigger)
                
                # Identify caller (nearest person before trigger)
                caller = "Unknown Person"
                if persons:
                    caller = persons[0]
                
                # Identify callee (nearest person after trigger or phone)
                callee = "Unknown Contact"
                if len(persons) > 1:
                    callee = persons[1]
                elif phones:
                    callee = phones[0]

                duration_sec = parse_duration_seconds(sent_text)

                calls.append({
                    "event_type": "CALL",
                    "caller": caller,
                    "callee": callee,
                    "duration_sec": duration_sec,
                    "timestamp": timestamp_str,
                    "source_sentence": sent_text,
                    "confidence": "extracted_from_text — requires investigator verification"
                })
                break

        # 2. TRANSACTION EVENT DETECTION
        for trigger in TRANSACTION_TRIGGERS:
            if trigger in sent_lower:
                sender = "Unknown Sender"
                receiver = "Unknown Receiver"
                if len(persons) >= 2:
                    sender = persons[0]
                    receiver = persons[1]
                elif len(persons) == 1:
                    sender = persons[0]
                
                # Amount extraction
                amount_val = 0.0
                currency = "INR"
                if money_ents:
                    amount_val = parse_numeric_amount(money_ents[0])
                else:
                    # Fallback regex search for bare numbers near currency words
                    curr_match = re.search(r"(?:₹|Rs\.?|INR|\$)\s*([\d,]+)", sent_text, re.IGNORECASE)
                    if curr_match:
                        amount_val = parse_numeric_amount(curr_match.group(1))

                # Landmark / Location extraction
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
                    "confidence": "extracted_from_text — requires investigator verification"
                })
                break

    return {
        "calls": calls,
        "transactions": transactions
    }
