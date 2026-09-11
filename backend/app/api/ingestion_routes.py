import uuid
import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query, Form, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import get_db
from app.config import settings
from app.models import (
    UserRole, CaseRecord, CaseStatus, DocumentRecord, DocumentType, CallRecord,
    TransactionRecord, EntityLookup, ForensicArtifact, ForensicMessage,
    ForensicFile, ForensicLocation
)
from app.security.auth import require_role
from app.security.encryption import encrypt_name, generate_hash_id
from app.security.custody import log_custody_action
from app.nlp.entity_extractor import extract_entities, extract_entities_detailed
from app.nlp.event_extractor import extract_events_from_text
from app.nlp.relation_extractor import extract_relationships
from app.nlp.call_detection import detect_suspicious_calls
from app.nlp.person_matching import resolve_case_identities
from app.nlp.text_extractor import extract_document_text
from app.financial.transaction_detection import detect_suspicious_transactions
from app.alerts.workflow import create_alert
from app.graph.build_graph import write_graph
from app.evidence.service import register_evidence
from app.forensics.zip_analyzer import analyze_and_extract_zip, check_case_provenance
from app.forensics.forensic_pipeline import parse_forensic_artifact
from app.forensics.co_location import detect_co_locations

router = APIRouter(prefix="/ingestion", tags=["Evidence & Report Ingestion"])

class ReportPayload(BaseModel):
    document_id: str
    document_type: str = DocumentType.FIR.value
    text: str
    case_id: str

class TextAnalysisPayload(BaseModel):
    text: str
    case_id: Optional[str] = "CASE-PREVIEW"
    document_id: Optional[str] = "PREVIEW-DOC"

@router.post("/analyze-text", summary="Interactive NLP analysis of unstructured FIR narrative with entities, events, relationships, and person matching")
def analyze_unstructured_text(
    payload: TextAnalysisPayload,
    current_user: dict = Depends(require_role([UserRole.INVESTIGATOR, UserRole.ADMINISTRATOR, UserRole.VIEWER]))
):
    """
    Perform on-demand NLP analysis on raw FIR / investigation narrative text:
    - Extracts standardized entities (PERSON, LOCATION, ORG, PHONE, EMAIL, IP_ADDRESS, VEHICLE, etc.)
    - Extracts events (CALL, TRANSACTION, MEETING, COMMUNICATION, LOCATION_PRESENCE)
    - Extracts precision relationships with provenance & confidence
    - Detects possible person identity matches requiring investigator review
    - Returns structured analytical leads without modifying database records
    """
    raw_text = payload.text.strip()
    if not raw_text:
        raise HTTPException(status_code=400, detail="Text cannot be empty.")

    case_id = (payload.case_id or "CASE-PREVIEW").strip()
    doc_id = (payload.document_id or "PREVIEW-DOC").strip()

    # 1. Standardized entity extraction
    entities = extract_entities(raw_text)
    detailed_entities = extract_entities_detailed(raw_text, case_id=case_id, source_document=doc_id)

    # 2. Event extraction
    events = extract_events_from_text(raw_text)

    # 3. Precision relationship extraction
    relationships = extract_relationships(
        entities=entities,
        events=events,
        case_id=case_id,
        document_id=doc_id,
        raw_text=raw_text
    )

    # 4. Candidate person identity resolution
    candidate_person_matches = resolve_case_identities(
        persons=entities.get("PERSON", []),
        case_id=case_id
    )

    total_entities_count = sum(len(v) for v in entities.values())
    total_events_count = (
        len(events.get("calls", [])) +
        len(events.get("transactions", [])) +
        len(events.get("meetings", [])) +
        len(events.get("communications", [])) +
        len(events.get("location_presence", []))
    )

    return {
        "status": "SUCCESS",
        "case_id": case_id,
        "document_id": doc_id,
        "summary": {
            "entities_detected": total_entities_count,
            "events_detected": total_events_count,
            "relationships_detected": len(relationships),
            "possible_person_matches": len(candidate_person_matches),
            "message": f"Text processed successfully: {total_entities_count} entities, {total_events_count} events, {len(relationships)} relationships detected."
        },
        "entities": entities,
        "detailed_entities": detailed_entities,
        "events": events,
        "relationships": relationships,
        "candidate_person_matches": candidate_person_matches,
        "disclaimer": "NLP outputs are investigative leads for human review, not verified judicial facts."
    }

@router.post("/report", summary="Ingest raw investigation narrative, extract entities/events, and update graph")
def ingest_investigation_report(
    payload: ReportPayload,
    current_user: dict = Depends(require_role([UserRole.INVESTIGATOR, UserRole.ADMINISTRATOR])),
    db: Session = Depends(get_db)
):
    case_id = payload.case_id.strip()
    doc_id = payload.document_id.strip()
    raw_text = payload.text.strip()
    actor_email = current_user.get("email", "INVESTIGATOR")
    role = current_user.get("role", "INVESTIGATOR")

    if not raw_text:
        raise HTTPException(status_code=400, detail="Report text cannot be empty.")

    # 1. Store Raw Document Record
    doc_record = DocumentRecord(
        document_id=doc_id,
        document_type=payload.document_type.upper(),
        text=raw_text,
        case_id=case_id,
        metadata_json={"submitted_by": actor_email}
    )
    db.add(doc_record)
    db.commit()

    # Log initial custody submission
    log_custody_action(
        db=db,
        case_id=case_id,
        action="INVESTIGATION_REPORT_SUBMITTED",
        details={"document_id": doc_id, "document_type": payload.document_type},
        user_id=actor_email,
        role=role,
        source_id=doc_id
    )

    # 2. Extract Entities
    entities = extract_entities(raw_text)

    # 3. Encrypt real PII in EntityLookup and create pseudonym mapping
    for person_name in entities.get("PERSON", []):
        hash_id = generate_hash_id(person_name)
        existing = db.query(EntityLookup).filter(EntityLookup.hash_id == hash_id).first()
        if not existing:
            encrypted_val, _ = encrypt_name(person_name)
            lookup = EntityLookup(
                hash_id=hash_id,
                encrypted_name=encrypted_val,
                entity_type="Person"
            )
            db.add(lookup)
    db.commit()

    # 4. Extract Events (CALL, TRANSACTION, MEETING, COMMUNICATION, LOCATION_PRESENCE)
    events = extract_events_from_text(raw_text)

    # Store Call Records
    for c in events.get("calls", []):
        c_rec = CallRecord(
            call_id=f"CALL-{uuid.uuid4().hex[:6].upper()}",
            caller=c.get("caller", "Unknown"),
            callee=c.get("callee", "Unknown"),
            duration_sec=c.get("duration_sec", 0),
            timestamp=c.get("timestamp", ""),
            case_id=case_id,
            source_document=doc_id,
            confidence=str(c.get("confidence", "extracted_from_text"))
        )
        db.add(c_rec)

    # Store Transaction Records
    for t in events.get("transactions", []):
        loc = t.get("location", {})
        t_rec = TransactionRecord(
            transaction_id=f"TXN-{uuid.uuid4().hex[:6].upper()}",
            sender=t.get("sender", "Unknown"),
            receiver=t.get("receiver", "Unknown"),
            amount=t.get("amount", 0.0),
            currency=t.get("currency", "INR"),
            timestamp=t.get("timestamp", ""),
            landmark=loc.get("landmark", ""),
            area=loc.get("area", ""),
            case_id=case_id,
            source_document=doc_id,
            detection_status="EXTRACTED"
        )
        db.add(t_rec)

    db.commit()

    # 5. Extract Graph Relationships with Provenance
    relations = extract_relationships(
        entities=entities,
        events=events,
        case_id=case_id,
        document_id=doc_id,
        raw_text=raw_text
    )

    # Transform relationships into graph ingestion format (using pseudonyms for nodes)
    graph_records = []
    for rel in relations:
        src = rel["source"]
        tgt = rel["target"]
        src_type = rel.get("source_type", "Entity")
        tgt_type = rel.get("target_type", "Entity")

        # Use deterministic hash_id for Person nodes
        src_id = generate_hash_id(src) if src_type == "Person" else src
        tgt_id = generate_hash_id(tgt) if tgt_type == "Person" else tgt

        graph_records.append({
            "source": src_id,
            "target": tgt_id,
            "source_type": src_type,
            "target_type": tgt_type,
            "source_label": src, # Public label
            "target_label": tgt,
            "relation": rel["type"],
            "type": rel["type"],
            "weight": 1.0,
            "timestamp": rel.get("properties", {}).get("timestamp", ""),
            "artifact_hash": generate_hash_id(doc_id + raw_text[:50]),
            "properties": rel.get("properties", {})
        })

    # Ingest to Neo4j / NetworkX
    graph_delta = write_graph(cid=case_id, records=graph_records, is_rebuild=False)

    # 6. Automated Pattern Detection -> Create PENDING Alerts
    alerts_created = []

    # Check Call Bursts
    flagged_calls = detect_suspicious_calls(events.get("calls", []))
    for fc in flagged_calls:
        alert = create_alert(
            db=db,
            case_id=case_id,
            alert_type="CALL_BURST",
            related_entities=[generate_hash_id(fc["caller"]), generate_hash_id(fc["callee"])],
            source_module="nlp.call_detection",
            reason=f"Suspicious call flags: {', '.join(fc.get('reasons', []))}"
        )
        alerts_created.append({"id": alert.id, "alert_type": "CALL_BURST", "reason": alert.reason, "status": "PENDING"})

    # Check Suspicious Transactions
    flagged_txns = detect_suspicious_transactions(events.get("transactions", []))
    for ft in flagged_txns:
        alert = create_alert(
            db=db,
            case_id=case_id,
            alert_type="TRANSACTION_PATTERN",
            related_entities=[generate_hash_id(ft["sender"]), generate_hash_id(ft["receiver"])],
            source_module="financial.transaction_detection",
            reason=f"Suspicious financial flags: {', '.join(ft.get('reasons', []))}"
        )
        alerts_created.append({"id": alert.id, "alert_type": "TRANSACTION_PATTERN", "reason": alert.reason, "status": "PENDING"})

    # Check Candidate Person Ambiguities
    candidate_matches = resolve_case_identities(entities.get("PERSON", []), case_id=case_id)
    for cm in candidate_matches:
        if cm.get("requires_review"):
            alert = create_alert(
                db=db,
                case_id=case_id,
                alert_type="POTENTIAL_MATCH",
                related_entities=[generate_hash_id(cm["person1"]), generate_hash_id(cm["person2"])],
                source_module="nlp.person_matching",
                reason=cm["recommendation"]
            )
            alerts_created.append({"id": alert.id, "alert_type": "POTENTIAL_MATCH", "reason": alert.reason, "status": "PENDING"})

    # 7. Log NLP and Graph events to Chain of Custody
    log_custody_action(
        db=db,
        case_id=case_id,
        action="NLP_ANALYSIS_COMPLETED",
        details={
            "document_id": doc_id,
            "entities_found": {k: len(v) for k, v in entities.items()},
            "calls_extracted": len(events.get("calls", [])),
            "transactions_extracted": len(events.get("transactions", [])),
            "meetings_extracted": len(events.get("meetings", [])),
            "relationships_extracted": len(relations)
        },
        user_id=actor_email,
        role=role,
        source_id=doc_id
    )

    log_custody_action(
        db=db,
        case_id=case_id,
        action="GRAPH_UPDATED",
        details={
            "nodes_added": len(graph_delta.get("nodes_added", [])),
            "edges_added": len(graph_delta.get("edges_added", []))
        },
        user_id=actor_email,
        role=role,
        source_id=doc_id
    )

    return {
        "document_id": doc_id,
        "case_id": case_id,
        "entities": entities,
        "events": events,
        "relationships_count": len(relations),
        "graph_delta": graph_delta,
        "alerts_created": alerts_created,
        "disclaimer": "Extracted entities, events, and relationships are investigative leads for human review, not verified facts."
    }

@router.post("/upload-report-document", summary="Upload narrative document (TXT, PDF, DOCX, JSON), extract text, and run NLP pipeline")
async def upload_report_document(
    file: UploadFile = File(...),
    case_id: str = Form(...),
    document_type: str = Form(DocumentType.FIR.value),
    current_user: dict = Depends(require_role([UserRole.INVESTIGATOR, UserRole.ADMINISTRATOR])),
    db: Session = Depends(get_db)
):
    """
    Ingest a document file (TXT, PDF, DOCX, JSON):
    1. Extract machine-readable text safely
    2. Check for image-only PDF requiring OCR
    3. Run NLP pipeline and update case records and graph
    """
    file_bytes = await file.read()
    fname = file.filename or "report_document.txt"
    case_id_clean = case_id.strip()

    extraction = extract_document_text(file_bytes=file_bytes, file_name=fname)
    extracted_text = extraction["text"]

    if not extracted_text:
        ocr_msg = extraction.get("ocr_message") or "Document contains no readable text."
        raise HTTPException(
            status_code=400,
            detail=f"Could not extract machine-readable text from '{fname}'. {ocr_msg}"
        )

    doc_id = f"DOC-{uuid.uuid4().hex[:8].upper()}"

    payload = ReportPayload(
        document_id=doc_id,
        document_type=document_type,
        text=extracted_text,
        case_id=case_id_clean
    )
    result = ingest_investigation_report(payload=payload, current_user=current_user, db=db)
    result["file_name"] = fname
    result["extracted_char_count"] = extraction["char_count"]
    if extraction.get("ocr_message"):
        result["ocr_notice"] = extraction["ocr_message"]

    return result

@router.post("/upload-forensic-zip", summary="Ingest digital forensic evidence ZIP archive with provenance check")
async def upload_forensic_zip(
    file: UploadFile = File(...),
    case_id: str = Query(..., description="Target case ID for evidence attribution"),
    current_user: dict = Depends(require_role([UserRole.INVESTIGATOR, UserRole.ADMINISTRATOR])),
    db: Session = Depends(get_db)
):
    zip_bytes = await file.read()
    actor_email = current_user.get("email", "INVESTIGATOR")
    role = current_user.get("role", "INVESTIGATOR")

    # 1. Register parent evidence file in database & storage
    ev_record = register_evidence(
        db=db,
        case_id=case_id,
        file_name=file.filename or "forensic_dump.zip",
        file_bytes=zip_bytes,
        file_type="ZIP",
        actor_id=actor_email,
        role=role
    )

    # 2. Safe unpack & child hashing
    extract_dir = settings.EVIDENCE_STORAGE_DIR / case_id / f"unpacked_{ev_record.evidence_id}"
    try:
        parent_sha, child_artifacts = analyze_and_extract_zip(zip_bytes, extract_dir)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to extract forensic ZIP: {str(e)}")

    parsed_all_records = []
    locations_for_coloc = []

    for art in child_artifacts:
        art_path = art["local_path"]
        parsed = parse_forensic_artifact(art_path)
        parsed_all_records.append({"artifact": art["filename"], "data": parsed})

        # Register child forensic artifact
        db_art = ForensicArtifact(
            evidence_id=ev_record.evidence_id,
            case_id=case_id,
            artifact_type=art["filename"].split(".")[-1].upper(),
            name=art["filename"],
            sha256_hash=art["sha256_hash"],
            size_bytes=art["size_bytes"]
        )
        db.add(db_art)

        # Collect locations for co-location analysis
        locations_for_coloc.extend(parsed.get("locations", []))

    db.commit()

    # 3. Provenance Check
    provenance = check_case_provenance(case_id, parsed_all_records)

    # 4. Detect Co-locations
    co_locs = detect_co_locations(locations_for_coloc)
    for cl in co_locs:
        create_alert(
            db=db,
            case_id=case_id,
            alert_type="CO_LOCATION",
            related_entities=[generate_hash_id(cl["person1"]), generate_hash_id(cl["person2"])],
            source_module="forensics.co_location",
            reason=f"Suspects co-located within {cl['distance_meters']}m at {cl['location_name']}"
        )

    return {
        "evidence_id": ev_record.evidence_id,
        "case_id": case_id,
        "parent_sha256": ev_record.sha256_hash,
        "artifacts_extracted": len(child_artifacts),
        "provenance": provenance,
        "co_locations_detected": len(co_locs),
        "integrity_status": ev_record.integrity_status,
        "disclaimer": "Forensic evidence integrity verified via SHA-256. Extracted artifacts require investigator review."
    }

@router.post("/case-bundle", summary="Ingest complete multi-artifact JSON investigation case bundle")
@router.post("/case-json", summary="Ingest complete multi-artifact JSON investigation case bundle (alias)")
def ingest_case_bundle(
    payload: Dict[str, Any],
    current_user: dict = Depends(require_role([UserRole.INVESTIGATOR, UserRole.ADMINISTRATOR])),
    db: Session = Depends(get_db)
):
    """
    Ingest a complete structured investigation bundle JSON containing:
    - Case metadata
    - People / Suspect profiles (encrypted in EntityLookup with deterministic hash_id)
    - Calls (stored in CallRecord + CALLED edges + burst detection)
    - Transactions (stored in TransactionRecord + TRANSACTED_WITH edges + structuring detection)
    - Chats (stored in ForensicMessage + CHATTED_WITH edges)
    - File transfers (stored in ForensicFile + TRANSFERRED_FILE edges)
    - Location pings (stored in ForensicLocation + Haversine co-location detection)
    - FIR Reports (NLP entity/event extraction)
    - Automatic Neo4j + NetworkX synchronized graph update
    - Immutable SHA-256 Digital Chain of Custody logging
    """
    actor_email = current_user.get("email", "INVESTIGATOR")
    role = current_user.get("role", "INVESTIGATOR")

    case_info = payload.get("case", {})
    case_id = (case_info.get("case_id") or payload.get("case_id") or "CASE-IMPORT").strip()
    case_title = case_info.get("note") or payload.get("note") or f"Investigation Case {case_id}"

    # 1. Upsert CaseRecord
    existing_case = db.query(CaseRecord).filter(CaseRecord.case_id == case_id).first()
    if not existing_case:
        existing_case = CaseRecord(
            case_id=case_id,
            case_number=case_id,
            title=case_title,
            status=CaseStatus.OPEN.value,
            created_by=actor_email
        )
        db.add(existing_case)
        db.commit()

    # 2. Ingest People (Suspects)
    id_to_name = {}
    id_to_hash = {}
    people_list = payload.get("people", [])

    for p in people_list:
        p_id = p.get("person_id") or p.get("id") or p.get("name")
        name = p.get("name") or p_id
        hash_id = generate_hash_id(name)
        id_to_name[p_id] = name
        id_to_hash[p_id] = hash_id

        existing_lookup = db.query(EntityLookup).filter(EntityLookup.hash_id == hash_id).first()
        if not existing_lookup:
            enc_name, _ = encrypt_name(name)
            lookup = EntityLookup(hash_id=hash_id, encrypted_name=enc_name, entity_type="Person")
            db.add(lookup)

    db.commit()

    graph_records = []
    alerts_created = []

    # 3. Ingest Calls
    calls_list = payload.get("calls", [])
    for c in calls_list:
        caller_id = c.get("caller_id") or c.get("caller") or "Unknown"
        callee_id = c.get("callee_id") or c.get("callee") or "Unknown"
        caller_name = id_to_name.get(caller_id, caller_id)
        callee_name = id_to_name.get(callee_id, callee_id)
        caller_hash = id_to_hash.get(caller_id, generate_hash_id(caller_name))
        callee_hash = id_to_hash.get(callee_id, generate_hash_id(callee_name))
        duration = int(c.get("duration_sec", 0))
        ts = str(c.get("timestamp", ""))

        c_rec = CallRecord(
            call_id=c.get("record_id") or f"CALL-{uuid.uuid4().hex[:6].upper()}",
            caller=caller_name,
            callee=callee_name,
            duration_sec=duration,
            timestamp=ts,
            case_id=case_id,
            source_document="case_bundle.json"
        )
        db.add(c_rec)

        graph_records.append({
            "source": caller_hash,
            "target": callee_hash,
            "source_type": "Person",
            "target_type": "Person",
            "source_label": caller_name,
            "target_label": callee_name,
            "relation": "CALLED",
            "type": "CALLED",
            "weight": 1.0,
            "timestamp": ts,
            "properties": {"duration_sec": duration, "case_id": case_id}
        })

    # 4. Ingest Transactions
    txns_list = payload.get("transactions", [])
    for t in txns_list:
        sender_id = t.get("sender_id") or t.get("sender") or "Unknown"
        receiver_id = t.get("receiver_id") or t.get("receiver") or "Unknown"
        sender_name = id_to_name.get(sender_id, sender_id)
        receiver_name = id_to_name.get(receiver_id, receiver_id)
        sender_hash = id_to_hash.get(sender_id, generate_hash_id(sender_name))
        receiver_hash = id_to_hash.get(receiver_id, generate_hash_id(receiver_name))
        amt = float(t.get("amount", 0.0))
        currency = t.get("currency", "INR")
        ts = str(t.get("timestamp", ""))

        t_rec = TransactionRecord(
            transaction_id=t.get("transaction_id") or f"TXN-{uuid.uuid4().hex[:6].upper()}",
            sender=sender_name,
            receiver=receiver_name,
            amount=amt,
            currency=currency,
            timestamp=ts,
            case_id=case_id,
            source_document="case_bundle.json",
            detection_status="PROCESSED"
        )
        db.add(t_rec)

        graph_records.append({
            "source": sender_hash,
            "target": receiver_hash,
            "source_type": "Person",
            "target_type": "Person",
            "source_label": sender_name,
            "target_label": receiver_name,
            "relation": "TRANSACTED_WITH",
            "type": "TRANSACTED_WITH",
            "weight": 1.0,
            "timestamp": ts,
            "properties": {"amount": amt, "currency": currency, "case_id": case_id}
        })

    # 5. Ingest Chats
    chats_list = payload.get("chats", [])
    for ch in chats_list:
        s_id = ch.get("sender_id") or "Unknown"
        r_id = ch.get("receiver_id") or "Unknown"
        s_name = id_to_name.get(s_id, s_id)
        r_name = id_to_name.get(r_id, r_id)
        s_hash = id_to_hash.get(s_id, generate_hash_id(s_name))
        r_hash = id_to_hash.get(r_id, generate_hash_id(r_name))

        msg = ForensicMessage(
            evidence_id=f"EV-CHAT-{case_id[:8]}",
            case_id=case_id,
            sender=s_name,
            receiver=r_name,
            platform=ch.get("platform", "Chat"),
            message_text=ch.get("message_text") or f"Chat interaction on {ch.get('platform', 'Chat')}",
            timestamp=ch.get("timestamp", "")
        )
        db.add(msg)

        graph_records.append({
            "source": s_hash,
            "target": r_hash,
            "source_type": "Person",
            "target_type": "Person",
            "source_label": s_name,
            "target_label": r_name,
            "relation": "CHATTED_WITH",
            "type": "CHATTED_WITH",
            "weight": 1.0,
            "timestamp": ch.get("timestamp", ""),
            "properties": {"platform": ch.get("platform", "Chat"), "case_id": case_id}
        })

    # 6. Ingest File Transfers
    files_list = payload.get("file_artifacts", [])
    for f in files_list:
        o_id = f.get("owner_id") or "Unknown"
        t_id = f.get("transferred_to_id")
        o_name = id_to_name.get(o_id, o_id)
        o_hash = id_to_hash.get(o_id, generate_hash_id(o_name))

        ff = ForensicFile(
            evidence_id=f"EV-FILE-{case_id[:8]}",
            case_id=case_id,
            filename=f.get("filename", "file.bin"),
            file_hash=f.get("hash_sha256", "0"*64),
            sender=o_name,
            receiver=id_to_name.get(t_id, t_id) if t_id else None,
            timestamp=f.get("timestamp", "")
        )
        db.add(ff)

        if t_id:
            t_name = id_to_name.get(t_id, t_id)
            t_hash = id_to_hash.get(t_id, generate_hash_id(t_name))
            graph_records.append({
                "source": o_hash,
                "target": t_hash,
                "source_type": "Person",
                "target_type": "Person",
                "source_label": o_name,
                "target_label": t_name,
                "relation": "TRANSFERRED_FILE",
                "type": "TRANSFERRED_FILE",
                "weight": 1.0,
                "timestamp": f.get("timestamp", ""),
                "properties": {"filename": f.get("filename"), "case_id": case_id}
            })

    # 7. Ingest Location Pings & Detect Co-Locations
    loc_pings = payload.get("location_pings", [])
    loc_for_coloc = []
    for lp in loc_pings:
        e_id = lp.get("entity_id") or "Unknown"
        p_name = id_to_name.get(e_id, e_id)
        p_hash = id_to_hash.get(e_id, generate_hash_id(p_name))
        lat = float(lp.get("lat", 0.0))
        lng = float(lp.get("lng", 0.0))
        ts = str(lp.get("timestamp", ""))

        fl = ForensicLocation(
            evidence_id=f"EV-LOC-{case_id[:8]}",
            case_id=case_id,
            person_name=p_name,
            latitude=lat,
            longitude=lng,
            timestamp=ts
        )
        db.add(fl)
        loc_for_coloc.append({
            "person_name": p_name,
            "latitude": lat,
            "longitude": lng,
            "timestamp": ts,
            "location_name": f"GPS ({lat:.4f}, {lng:.4f})"
        })

    # Co-location analysis
    co_locs = detect_co_locations(loc_for_coloc, distance_threshold_meters=500.0)
    for cl in co_locs:
        alert = create_alert(
            db=db,
            case_id=case_id,
            alert_type="CO_LOCATION",
            related_entities=[generate_hash_id(cl["person1"]), generate_hash_id(cl["person2"])],
            source_module="forensics.co_location",
            reason=f"Suspects co-located within {cl['distance_meters']}m at {cl['location_name']}"
        )
        alerts_created.append({"id": alert.id, "alert_type": "CO_LOCATION", "reason": alert.reason, "status": "PENDING"})

    # 8. Ingest FIR Narrative Reports with NLP
    fir_list = payload.get("fir_reports", [])
    for fir in fir_list:
        fir_text = fir.get("text", "")
        fir_id = fir.get("fir_id", f"FIR-{case_id}")
        if fir_text:
            doc_rec = DocumentRecord(
                document_id=fir_id,
                document_type="FIR",
                text=fir_text,
                case_id=case_id,
                metadata_json={"submitted_by": actor_email}
            )
            db.add(doc_rec)
            ents = extract_entities(fir_text)
            for p_name in ents.get("PERSON", []):
                h_id = generate_hash_id(p_name)
                graph_records.append({
                    "source": h_id,
                    "target": case_id,
                    "source_type": "Person",
                    "target_type": "Case",
                    "source_label": p_name,
                    "target_label": case_id,
                    "relation": "MENTIONED_IN",
                    "type": "MENTIONED_IN",
                    "weight": 1.0,
                    "properties": {"document_id": fir_id}
                })

    db.commit()

    # 9. Pattern Detections (Bursts & Financial structuring)
    flagged_calls = detect_suspicious_calls([
        {"caller": id_to_name.get(c.get("caller_id"), c.get("caller_id")),
         "callee": id_to_name.get(c.get("callee_id"), c.get("callee_id")),
         "duration_sec": c.get("duration_sec", 0),
         "timestamp": c.get("timestamp", "")}
        for c in calls_list
    ])
    for fc in flagged_calls:
        alert = create_alert(
            db=db,
            case_id=case_id,
            alert_type="CALL_BURST",
            related_entities=[generate_hash_id(fc["caller"]), generate_hash_id(fc["callee"])],
            source_module="nlp.call_detection",
            reason=f"Suspicious call flags: {', '.join(fc.get('reasons', []))}"
        )
        alerts_created.append({"id": alert.id, "alert_type": "CALL_BURST", "reason": alert.reason, "status": "PENDING"})

    flagged_txns = detect_suspicious_transactions([
        {"transaction_id": t.get("transaction_id", "TXN"),
         "sender": id_to_name.get(t.get("sender_id"), t.get("sender_id")),
         "receiver": id_to_name.get(t.get("receiver_id"), t.get("receiver_id")),
         "amount": t.get("amount", 0.0),
         "currency": t.get("currency", "INR"),
         "timestamp": t.get("timestamp", "")}
        for t in txns_list
    ])
    for ft in flagged_txns:
        alert = create_alert(
            db=db,
            case_id=case_id,
            alert_type="TRANSACTION_PATTERN",
            related_entities=[generate_hash_id(ft["sender"]), generate_hash_id(ft["receiver"])],
            source_module="financial.transaction_detection",
            reason=f"Suspicious financial flags: {', '.join(ft.get('reasons', []))}"
        )
        alerts_created.append({"id": alert.id, "alert_type": "TRANSACTION_PATTERN", "reason": alert.reason, "status": "PENDING"})

    # Link all suspects to the Case node
    for p_id, name in id_to_name.items():
        h_id = id_to_hash[p_id]
        graph_records.append({
            "source": h_id,
            "target": case_id,
            "source_type": "Person",
            "target_type": "Case",
            "source_label": name,
            "target_label": case_id,
            "relation": "SUBJECT_OF",
            "type": "SUBJECT_OF",
            "weight": 1.0,
            "properties": {"case_id": case_id}
        })

    # 10. Update Neo4j and NetworkX Graph
    graph_delta = write_graph(cid=case_id, records=graph_records, is_rebuild=False)

    # 11. Log to Digital Chain of Custody
    log_custody_action(
        db=db,
        case_id=case_id,
        action="CASE_BUNDLE_INGESTED",
        details={
            "case_id": case_id,
            "people_count": len(people_list),
            "calls_count": len(calls_list),
            "transactions_count": len(txns_list),
            "chats_count": len(chats_list),
            "file_artifacts_count": len(files_list),
            "location_pings_count": len(loc_pings),
            "nodes_added": len(graph_delta.get("nodes_added", [])),
            "edges_added": len(graph_delta.get("edges_added", []))
        },
        user_id=actor_email,
        role=role,
        source_id=case_id
    )

    return {
        "case_id": case_id,
        "title": case_title,
        "summary": {
            "people_registered": len(people_list),
            "calls_indexed": len(calls_list),
            "transactions_recorded": len(txns_list),
            "chats_parsed": len(chats_list),
            "file_artifacts_stored": len(files_list),
            "location_pings_logged": len(loc_pings),
            "co_locations_detected": len(co_locs),
            "alerts_created": len(alerts_created)
        },
        "graph_delta": {
            "nodes_count": len(graph_delta.get("nodes_added", [])),
            "edges_count": len(graph_delta.get("edges_added", []))
        },
        "alerts": alerts_created,
        "chain_of_custody_logged": True,
        "disclaimer": "All extracted entities and network connections are decision-support leads requiring investigator confirmation."
    }
