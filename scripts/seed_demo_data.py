import sys
import os
import datetime
from pathlib import Path

# Add backend directory and container app directory to path
script_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(script_dir.parent / "backend"))
sys.path.insert(0, str(script_dir.parent))
sys.path.insert(0, "/app")

# Ensure utf-8 output encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from app.database import SessionLocal, init_db
from app.cases.service import create_case
from app.nlp.entity_extractor import extract_entities
from app.nlp.event_extractor import extract_events_from_text
from app.nlp.relation_extractor import extract_relationships
from app.security.encryption import encrypt_name, generate_hash_id
from app.security.custody import log_custody_action, verify_custody_chain
from app.graph.build_graph import write_graph
from app.evidence.service import register_evidence, verify_evidence_integrity
from app.alerts.workflow import create_alert, confirm_alert
from app.models import DocumentRecord, CallRecord, TransactionRecord, EntityLookup, PersonMatch

def seed_demo_case():
    print("==================================================")
    print("SEEDING PS 26189 AI CRIMINAL NETWORK ANALYSIS DATA")
    print("==================================================")

    init_db()
    db = SessionLocal()

    case_id = "CASE-2026-DELHI-001"
    
    # 1. Create Case
    try:
        case = create_case(
            db=db,
            case_id=case_id,
            case_number="FIR/2026/CYBER/0912",
            title="Operation Hawk Eye - Inter-State Hawala & Syndicate Network",
            description="Intelligence report regarding structured illicit transactions, burner phone communications, and shell enterprise affiliations in National Capital Region.",
            created_by="inspector.verma@delhipolice.gov.in"
        )
        print(f"[OK] Created Case: {case.case_id} - '{case.title}'")
    except ValueError:
        print(f"[INFO] Case {case_id} already exists, proceeding with updates.")

    # 2. Ingest Multiple Investigation Reports
    reports = [
        {
            "doc_id": "FIR-2026-001",
            "doc_type": "FIR",
            "text": (
                "Rohan Sharma, chief operator of Shakti Traders, was seen meeting Vikas Yadav near Sector 22 market on 5th January. "
                "Rohan called Vikas for about 14 minutes at around 11:45 PM regarding illicit cash consignments. "
                "Contact number 9876543210 was used by Rohan, while vehicle DL-01-AB-1234 was parked nearby."
            )
        },
        {
            "doc_id": "INTEL-2026-042",
            "doc_type": "INTEL_REPORT",
            "text": (
                "Surveillance at Cyber City confirmed Suresh Raina handing over financial tokens to Rohan Sharma. "
                "On 6th January around 3 PM, Rohan transferred Rs 49500 to Vikas Yadav through the State Bank branch near Sector 22 market. "
                "Later at 3:30 PM, Rohan transferred another Rs 48000 to Vikas Yadav. "
                "Suresh Raina is closely affiliated with Apex Logistics."
            )
        },
        {
            "doc_id": "SURVEILLANCE-2026-088",
            "doc_type": "SURVEILLANCE",
            "text": (
                "Intercepted communications reveal Vikram Malhotra coordinating with Suresh Raina at Aerocity. "
                "Vikram Malhotra transferred Rs 350000 to Rohan Sharma through State Bank Cyber Hub on 7th January. "
                "Suresh Raina called Vikram Malhotra for 8 minutes at 01:20 AM."
            )
        }
    ]

    all_graph_records = []

    for r in reports:
        doc_rec = DocumentRecord(
            document_id=r["doc_id"],
            document_type=r["doc_type"],
            text=r["text"],
            case_id=case_id,
            metadata_json={"source": "Special Cell Surveillance"}
        )
        db.add(doc_rec)

        # Log custody
        log_custody_action(
            db=db,
            case_id=case_id,
            action="INVESTIGATION_REPORT_SUBMITTED",
            details={"document_id": r["doc_id"], "type": r["doc_type"]},
            user_id="inspector.verma@delhipolice.gov.in",
            role="INVESTIGATOR",
            source_id=r["doc_id"]
        )

        entities = extract_entities(r["text"])
        events = extract_events_from_text(r["text"])

        # PII Encryption
        for p in entities.get("PERSON", []):
            hid = generate_hash_id(p)
            existing = db.query(EntityLookup).filter(EntityLookup.hash_id == hid).first()
            if not existing:
                enc, _ = encrypt_name(p)
                db.add(EntityLookup(hash_id=hid, encrypted_name=enc, entity_type="Person"))

        # Calls
        for c in events.get("calls", []):
            db.add(CallRecord(
                call_id=f"CDR-{r['doc_id']}-{c['caller'][:3]}",
                caller=c["caller"],
                callee=c["callee"],
                duration_sec=c["duration_sec"],
                timestamp=c["timestamp"],
                case_id=case_id,
                source_document=r["doc_id"]
            ))

        # Transactions
        for t in events.get("transactions", []):
            db.add(TransactionRecord(
                transaction_id=f"TXN-{r['doc_id']}-{t['sender'][:3]}",
                sender=t["sender"],
                receiver=t["receiver"],
                amount=t["amount"],
                currency=t["currency"],
                timestamp=t["timestamp"],
                landmark=t["location"].get("landmark", ""),
                area=t["location"].get("area", ""),
                case_id=case_id,
                source_document=r["doc_id"],
                detection_status="FLAGGED" if t["amount"] >= 200000 or t["amount"] == 49500 else "NORMAL"
            ))

        db.commit()

        # Relations
        relations = extract_relationships(entities, events, case_id=case_id, document_id=r["doc_id"])
        for rel in relations:
            src = rel["source"]
            tgt = rel["target"]
            src_t = rel["source_type"]
            tgt_t = rel["target_type"]
            all_graph_records.append({
                "source": generate_hash_id(src) if src_t == "Person" else src,
                "target": generate_hash_id(tgt) if tgt_t == "Person" else tgt,
                "source_type": src_t,
                "target_type": tgt_t,
                "source_label": src,
                "target_label": tgt,
                "relation": rel["type"],
                "type": rel["type"],
                "weight": 1.0,
                "timestamp": rel.get("properties", {}).get("timestamp", ""),
                "artifact_hash": generate_hash_id(r["doc_id"]),
                "properties": rel.get("properties", {})
            })

    # 3. Write Graph
    write_graph(cid=case_id, records=all_graph_records, is_rebuild=True)
    print(f"[OK] Constructed Case Graph with {len(all_graph_records)} relationships.")

    # 4. Upload Digital Evidence Artifacts
    sample_evidence_files = [
        ("seized_call_detail_records.pdf", b"%PDF-1.5 FORENSIC CALL LOG DUMP 9876543210 -> 9811002233 2026", "PDF"),
        ("intercepted_bank_statements.csv", b"transaction_id,sender,receiver,amount,timestamp\nTXN-01,Rohan,Vikas,49500,2026-01-06T15:00\nTXN-02,Rohan,Vikas,48000,2026-01-06T15:30", "CSV"),
        ("mobile_device_chat_extraction.json", b'{"chat_messages": [{"sender": "Rohan", "receiver": "Vikas", "text": "Cash ready at Sector 22"}]}', "JSON")
    ]

    for fname, fbytes, ftype in sample_evidence_files:
        ev = register_evidence(
            db=db,
            case_id=case_id,
            file_name=fname,
            file_bytes=fbytes,
            file_type=ftype,
            actor_id="inspector.verma@delhipolice.gov.in",
            role="INVESTIGATOR"
        )
        print(f"[OK] Registered Evidence: {ev.evidence_id} - '{ev.file_name}' (SHA-256: {ev.sha256_hash[:16]}...)")

    # 5. Create Person Matches
    db.add(PersonMatch(
        person1="Rohan Sharma",
        person2="Rohan S.",
        matching_score=95.0,
        matching_reason="phone_number_match, high_name_similarity",
        case_id=case_id
    ))
    db.commit()

    # 6. Create Alerts & Confirm One
    a1 = create_alert(
        db=db,
        case_id=case_id,
        alert_type="TRANSACTION_PATTERN",
        related_entities=[generate_hash_id("Rohan Sharma"), generate_hash_id("Vikas Yadav")],
        source_module="financial.transaction_detection",
        reason="Smurfing / Structuring Signature: Multiple Rs 49,500 and Rs 48,000 transactions within 30 minutes below Rs 50,000 threshold"
    )
    a2 = create_alert(
        db=db,
        case_id=case_id,
        alert_type="CALL_BURST",
        related_entities=[generate_hash_id("Suresh Raina"), generate_hash_id("Vikram Malhotra")],
        source_module="nlp.call_detection",
        reason="Nocturnal high-frequency communication at 01:20 AM"
    )

    confirm_alert(
        db=db,
        alert_id=a1.id,
        reviewer_id="inspector.verma@delhipolice.gov.in",
        reviewer_role="INVESTIGATOR",
        notes="Verified against bank ledger statement and confirmed as Hawala structuring."
    )
    print("[OK] Initialized Alerts (1 Confirmed, 1 Pending).")

    # 7. Verify Chain of Custody
    custody_result = verify_custody_chain(db=db, case_id=case_id)
    print("\n--- DIGITAL CHAIN OF CUSTODY VERIFICATION ---")
    print(f"Case ID: {custody_result['case_id']}")
    print(f"Chain Integrity: {'[VALID] INTACT & VERIFIED' if custody_result['chain_valid'] else '[FAIL] COMPROMISED'}")
    print(f"Total Verifiable Hash Links: {custody_result['records_checked']}")
    print(f"Genesis / First Hash: {custody_result['first_hash'][:24]}...")
    print(f"Latest Case Hash:     {custody_result['latest_hash'][:24]}...")
    print("==================================================")
    print("DEMO SEEDING COMPLETED SUCCESSFULLY!")
    print("==================================================")

if __name__ == "__main__":
    seed_demo_case()
