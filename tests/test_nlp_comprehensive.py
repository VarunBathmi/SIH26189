import pytest
from app.nlp.entity_extractor import (
    extract_entities,
    extract_entities_detailed,
    validate_ip_address,
    deduplicate_entities_fuzzy
)
from app.nlp.event_extractor import extract_events_from_text
from app.nlp.relation_extractor import extract_relationships
from app.nlp.person_matching import match_person, normalize_person_name, resolve_case_identities
from app.nlp.text_extractor import (
    extract_document_text,
    extract_text_from_txt,
    extract_text_from_json_dict
)

# ------------------------------------------------------------------------------
# TEST 1: Exact Jaipur FIR Narrative from Problem Statement
# ------------------------------------------------------------------------------
def test_jaipur_fir_narrative_extraction():
    fir_text = (
        "On 12 March 2026, Rahul Sharma contacted Amit Kumar through a mobile phone. "
        "Later, Rahul was seen near Jaipur Railway Station at approximately 9:30 PM. "
        "Amit transferred funds to an account associated with Rahul."
    )
    entities = extract_entities(fir_text)
    events = extract_events_from_text(fir_text)
    relationships = extract_relationships(
        entities=entities,
        events=events,
        case_id="CASE-2026-JAIPUR-014",
        document_id="FIR-JAIPUR-001",
        raw_text=fir_text
    )

    # Entity verifications
    assert any("Rahul" in p for p in entities["PERSON"])
    assert any("Amit" in p for p in entities["PERSON"])
    assert any("Jaipur" in loc for loc in entities["LOCATION"])
    assert any("12 March 2026" in d for d in entities["DATE"])
    assert any("9:30 PM" in t or "9:30" in t for t in entities["TIME"])

    # Event verifications
    comms = events.get("communications", []) + events.get("calls", [])
    assert len(comms) >= 1

    presence = events.get("location_presence", [])
    assert len(presence) >= 1
    assert any("Jaipur" in p["location"] for p in presence)

    txns = events.get("transactions", [])
    assert len(txns) >= 1
    assert any("Amit" in t["sender"] for t in txns)

    # Relationship verifications
    rel_types = [r["type"] for r in relationships]
    assert "COMMUNICATED_WITH" in rel_types or "CALLED" in rel_types
    assert "LOCATED_AT" in rel_types
    assert "TRANSACTED_WITH" in rel_types
    assert "MENTIONED_IN" in rel_types

# ------------------------------------------------------------------------------
# TEST 2 & 3: Multiple People and Multiple Locations
# ------------------------------------------------------------------------------
def test_multiple_people_and_locations():
    text = (
        "Inspector Verma met Suresh Raina and Rohan Sharma at Cyber City in Gurugram. "
        "Later, Vikas Yadav arrived from Jaipur to join them at Sector 22 Market."
    )
    entities = extract_entities(text)
    persons = entities["PERSON"]
    locations = entities["LOCATION"]

    assert len(persons) >= 3
    assert any("Raina" in p or "Suresh" in p for p in persons)
    assert any("Rohan" in p or "Sharma" in p for p in persons)
    assert any("Vikas" in p or "Yadav" in p for p in persons)

    assert any("Cyber City" in l or "Gurugram" in l for l in locations)
    assert any("Jaipur" in l or "Sector 22" in l for l in locations)

# ------------------------------------------------------------------------------
# TEST 4 & 5: Dates, Times, and Indian Phone Numbers (+91 format)
# ------------------------------------------------------------------------------
def test_dates_times_and_phone_numbers():
    text = (
        "On 15 January 2026 at 02:45 AM, suspect dialed +91-9876543210 and 9811002233. "
        "Another call occurred on 16/01/2026 at 11:30 PM."
    )
    entities = extract_entities(text)
    phones = entities["PHONE"]
    dates = entities["DATE"]
    times = entities["TIME"]

    assert any("9876543210" in p for p in phones)
    assert any("9811002233" in p for p in phones)
    assert len(dates) >= 1
    assert len(times) >= 1

# ------------------------------------------------------------------------------
# TEST 6: IP Addresses - Valid Octets vs Invalid Numbers
# ------------------------------------------------------------------------------
def test_ip_address_validation():
    valid_text = "Suspect connected via 192.168.1.105 and 10.0.0.1 on server 2001:0db8:85a3:0000:0000:8a2e:0370:7334."
    invalid_text = "Fake IP addresses like 999.999.999.999 and 300.1.2.3 should not be matched as valid IPs."

    valid_ents = extract_entities(valid_text)
    assert "192.168.1.105" in valid_ents["IP_ADDRESS"]
    assert "10.0.0.1" in valid_ents["IP_ADDRESS"]

    invalid_ents = extract_entities(invalid_text)
    assert "999.999.999.999" not in invalid_ents["IP_ADDRESS"]
    assert "300.1.2.3" not in invalid_ents["IP_ADDRESS"]

    assert validate_ip_address("192.168.1.1") is True
    assert validate_ip_address("999.1.1.1") is False

# ------------------------------------------------------------------------------
# TEST 7: Devices, Vehicles, and Bank Accounts
# ------------------------------------------------------------------------------
def test_devices_vehicles_and_bank_accounts():
    text = (
        "Vehicle DL-01-AB-1234 and RJ-14-CA-5678 were seized. "
        "Device IMEI: 867530912345678 and MAC 00:1A:2B:3C:4D:5E were logged. "
        "Funds were sent to A/C No: 1234567890123."
    )
    entities = extract_entities(text)
    assert any("DL-01-AB-1234" in v for v in entities["VEHICLE"])
    assert any("RJ-14-CA-5678" in v for v in entities["VEHICLE"])
    assert any("867530912345678" in d for d in entities["DEVICE"])
    assert any("00:1A:2B:3C:4D:5E" in d for d in entities["DEVICE"])
    assert any("1234567890123" in a for a in entities["BANK_ACCOUNT"])

# ------------------------------------------------------------------------------
# TEST 8 & 9: Financial Transactions and Meeting Events
# ------------------------------------------------------------------------------
def test_financial_transactions_and_meetings():
    text = (
        "Vikram Malhotra met Suresh Raina at Aerocity on 7th January. "
        "Vikram Malhotra transferred ₹350,000 to Suresh Raina through State Bank."
    )
    events = extract_events_from_text(text)
    meetings = events.get("meetings", [])
    transactions = events.get("transactions", [])

    assert len(meetings) >= 1
    assert "Aerocity" in meetings[0]["location"] or any("Aerocity" in str(m) for m in meetings)

    assert len(transactions) >= 1
    assert transactions[0]["amount"] == 350000.0
    assert "Vikram" in transactions[0]["sender"]
    assert "Suresh" in transactions[0]["receiver"]

# ------------------------------------------------------------------------------
# TEST 10: Multi-paragraph Investigation Narrative
# ------------------------------------------------------------------------------
def test_multi_paragraph_investigation_narrative():
    multi_para = (
        "Paragraph 1:\n"
        "On 5th January, Rohan Sharma called Vikas Yadav for 14 minutes at 11:45 PM. "
        "They discussed shipments for Shakti Traders.\n\n"
        "Paragraph 2:\n"
        "On 6th January, Rohan Sharma transferred Rs 50,000 to Vikas Yadav at Sector 22 market. "
        "Surveillance vehicle DL-01-AB-1234 was recorded nearby."
    )
    entities = extract_entities(multi_para)
    events = extract_events_from_text(multi_para)

    assert len(entities["PERSON"]) >= 2
    assert len(events["calls"]) >= 1
    assert len(events["transactions"]) >= 1

# ------------------------------------------------------------------------------
# TEST 11: Person Name Variations Normalization
# ------------------------------------------------------------------------------
def test_person_name_variations_and_resolution():
    res1 = match_person("Rahul Sharma", "Rahul Sharma")
    assert res1["status"] == "CONFIRMED_MATCH"
    assert res1["score"] == 100.0

    res2 = match_person("Rahul Sharma", "R. Sharma")
    assert res2["status"] == "POSSIBLE_MATCH"
    assert res2["requires_human_review"] is True

    res3 = match_person("Shri Rahul Sharma", "Rahul S.", phone1="9876543210", phone2="9876543210")
    assert res3["status"] == "CONFIRMED_MATCH"
    assert res3["score"] == 100.0

    # Batch case resolution
    names = ["Rahul Sharma", "Rahul S.", "Amit Kumar"]
    matches = resolve_case_identities(names, case_id="CASE-TEST-01")
    assert len(matches) >= 1
    assert any("Rahul" in m["person1"] and "Rahul" in m["person2"] for m in matches)

# ------------------------------------------------------------------------------
# TEST 12: CRITICAL NEGATIVE TEST - Unrelated Individuals in Same Document
# ------------------------------------------------------------------------------
def test_negative_isolation_unrelated_people_no_edge():
    """
    Verify requirement 16:
    'Rahul Sharma lives in Jaipur. Amit Kumar works in Delhi.
    The investigation separately mentions both individuals.'
    The graph must NOT automatically create a relationship edge between Rahul and Amit.
    """
    text = (
        "Rahul Sharma lives in Jaipur. "
        "Amit Kumar works in Delhi. "
        "The investigation separately mentions both individuals."
    )
    entities = extract_entities(text)
    events = extract_events_from_text(text)
    relationships = extract_relationships(
        entities=entities,
        events=events,
        case_id="CASE-TEST-ISOLATION",
        document_id="DOC-NEG-01",
        raw_text=text
    )

    # Check direct links between Rahul and Amit
    direct_links = [
        r for r in relationships
        if (("Rahul" in r["source"] and "Amit" in r["target"]) or
            ("Amit" in r["source"] and "Rahul" in r["target"]))
        and r["type"] in ("MENTIONED_WITH", "RELATED_TO", "ASSOCIATED_WITH", "CALLED", "TRANSACTED_WITH", "MET_WITH")
    ]

    assert len(direct_links) == 0, f"False-positive direct relationship detected between unrelated individuals: {direct_links}"

    # Verify each person is correctly linked to their respective location
    rahul_locs = [r for r in relationships if "Rahul" in r["source"] and "Jaipur" in r["target"]]
    amit_locs = [r for r in relationships if "Amit" in r["source"] and "Delhi" in r["target"]]
    assert len(rahul_locs) >= 1
    assert len(amit_locs) >= 1

    # Verify Rahul is NOT linked to Delhi, and Amit is NOT linked to Jaipur
    false_rahul_delhi = [r for r in relationships if "Rahul" in r["source"] and "Delhi" in r["target"]]
    false_amit_jaipur = [r for r in relationships if "Amit" in r["source"] and "Jaipur" in r["target"]]
    assert len(false_rahul_delhi) == 0
    assert len(false_amit_jaipur) == 0

# ------------------------------------------------------------------------------
# TEST 13: Case Isolation - Case A vs Case B Graph Scoping
# ------------------------------------------------------------------------------
def test_case_isolation_scoping():
    text = "Suspect Alpha called Suspect Beta at 10 PM."
    events = extract_events_from_text(text)
    entities = {"PERSON": ["Suspect Alpha", "Suspect Beta"], "LOCATION": [], "ORGANIZATION": []}

    case1_rels = extract_relationships(entities, events, case_id="CASE-A", document_id="DOC-A", raw_text=text)
    case2_rels = extract_relationships(entities, events, case_id="CASE-B", document_id="DOC-B", raw_text=text)

    assert all(r["properties"]["case_id"] == "CASE-A" for r in case1_rels)
    assert all(r["properties"]["case_id"] == "CASE-B" for r in case2_rels)

# ------------------------------------------------------------------------------
# TEST 14: Empty and Invalid Text Resilience
# ------------------------------------------------------------------------------
def test_empty_and_invalid_text_resilience():
    empty_ents = extract_entities("")
    assert empty_ents["PERSON"] == []
    assert empty_ents["PHONE"] == []

    empty_events = extract_events_from_text("   \n\t  ")
    assert empty_events["calls"] == []
    assert empty_events["transactions"] == []

    empty_rels = extract_relationships(empty_ents, empty_events, "CASE-0", "DOC-0")
    assert empty_rels == []

# ------------------------------------------------------------------------------
# TEST 15: Multi-Format Text Extraction
# ------------------------------------------------------------------------------
def test_multi_format_text_extraction():
    # Plain text
    txt_res = extract_document_text(b"First Information Report content line 1", "fir.txt")
    assert "First Information Report" in txt_res["text"]
    assert txt_res["requires_ocr"] is False

    # JSON extraction
    json_bytes = b'{"case_id": "C-1", "narrative": "Suspect seen near railway station", "metadata": {"status": "open"}}'
    json_res = extract_document_text(json_bytes, "report.json")
    assert "Suspect seen near railway station" in json_res["text"]

    # Scanned PDF indicator test
    scanned_pdf_bytes = b"%PDF-1.4 header without text streams"
    pdf_res = extract_document_text(scanned_pdf_bytes, "scanned_doc.pdf")
    assert pdf_res["requires_ocr"] is True
    assert "OCR engine integration" in pdf_res["ocr_message"]

# ------------------------------------------------------------------------------
# TEST 16: Detailed Entities with Provenance and Confidence
# ------------------------------------------------------------------------------
def test_detailed_entities_provenance_and_confidence():
    text = "Vikas Yadav was contacted at 9876543210 regarding case CASE-2026-DELHI-001."
    detailed = extract_entities_detailed(text, case_id="CASE-2026-DELHI-001", source_document="FIR-01.txt")
    
    assert len(detailed) >= 2
    for ent in detailed:
        assert "text" in ent
        assert "type" in ent
        assert "confidence" in ent
        assert 0.0 <= ent["confidence"] <= 1.0
        assert ent["case_id"] == "CASE-2026-DELHI-001"
        assert ent["source_document"] == "FIR-01.txt"
        assert "extraction_method" in ent
