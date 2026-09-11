import pytest
from app.nlp.entity_extractor import extract_entities
from app.nlp.event_extractor import extract_events_from_text
from app.nlp.person_matching import match_person
from app.nlp.call_detection import detect_suspicious_calls

def test_nlp_entity_extraction_includes_organization():
    text = "Vikas Yadav, linked to Shakti Traders, met Suresh Raina at Cyber City using 9876543210. Vehicle DL-01-AB-1234 was present."
    entities = extract_entities(text)
    
    assert any("Vikas" in p or "Yadav" in p for p in entities["PERSON"])
    assert "Shakti Traders" in entities["ORGANIZATION"]
    assert "9876543210" in entities["PHONE"]
    assert any("DL-01-AB-1234" in v for v in entities["VEHICLE"])

def test_event_extraction_calls_and_transactions():
    narrative = (
        "Rohan Sharma called Vikas Yadav for about 12 minutes at around 11:40 PM on 5th January. "
        "On 6th January around 3 PM, Rohan Sharma transferred ₹50,000 to Vikas Yadav through the State Bank branch near Sector 22 market."
    )
    events = extract_events_from_text(narrative)
    
    calls = events.get("calls", [])
    assert len(calls) >= 1
    call = calls[0]
    assert "Rohan" in call["caller"]
    assert "Vikas" in call["callee"]
    assert call["duration_sec"] == 720 # 12 minutes

    txns = events.get("transactions", [])
    assert len(txns) >= 1
    txn = txns[0]
    assert "Rohan" in txn["sender"]
    assert "Vikas" in txn["receiver"]
    assert txn["amount"] == 50000.0
    assert "State Bank" in txn["location"]["landmark"] or "Sector 22" in txn["location"]["area"]

def test_person_fuzzy_matching():
    # Test phone match + similar name
    res = match_person("Rohan Sharma", "Rohan S.", phone1="9876543210", phone2="9876543210")
    assert res["match"] is True
    assert res["is_high_confidence"] is True
    assert "phone_number_match" in res["reason"]

    # Test distinct people
    diff = match_person("Amit Kumar", "Sunil Verma", phone1="9811111111", phone2="9822222222")
    assert diff["match"] is False

def test_call_burst_detection():
    calls = [
        {"call_id": "C1", "caller": "A", "callee": "B", "duration_sec": 450, "timestamp": "02:30 AM"},
        {"call_id": "C2", "caller": "A", "callee": "B", "duration_sec": 50, "timestamp": "02:40 AM"},
        {"call_id": "C3", "caller": "A", "callee": "B", "duration_sec": 120, "timestamp": "03:10 AM"}
    ]
    flagged = detect_suspicious_calls(calls, long_duration_threshold_sec=300, burst_count_threshold=3)
    assert len(flagged) >= 1
    reasons_str = str(flagged[0]["reasons"])
    assert "long_duration" in reasons_str or "nocturnal_activity" in reasons_str or "repeated_contact_burst" in reasons_str
