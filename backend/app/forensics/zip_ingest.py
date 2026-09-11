import os
import io
import json
import shutil
import zipfile
import tempfile
import logging
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
from sqlalchemy.orm import Session

from app.config import settings
from app.evidence.hash_engine import generate_sha256
from app.models import (
    CaseRecord, CaseStatus, DocumentRecord, CallRecord, TransactionRecord,
    ForensicArtifact, ForensicMessage, ForensicFile, ForensicLocation, EntityLookup
)
from app.security.encryption import encrypt_name, generate_hash_id
from app.security.custody import log_custody_action
from app.graph.neo4j_engine import neo4j_engine
from app.nlp.text_extractor import extract_document_text
from app.forensics.normalizers import (
    normalize_calls_csv,
    normalize_chats_csv,
    normalize_files_csv,
    normalize_locations_csv,
    normalize_browser_history_csv,
    normalize_entities_csv
)

logger = logging.getLogger(__name__)

# Safety caps
MAX_UNCOMPRESSED_BYTES = 200 * 1024 * 1024 # 200 MB
MAX_FILES_COUNT = 500

def ingest_forensic_zip(
    zip_bytes: bytes,
    db: Session,
    case_id_override: Optional[str] = None,
    actor_id: str = "INVESTIGATOR",
    role: str = "INVESTIGATOR"
) -> Dict[str, Any]:
    """
    Ingest a forensic evidence ZIP archive:
    1. Validates ZIP integrity and zip-bomb / traversal safety
    2. Hashes parent ZIP and all extracted files with SHA-256 for digital chain of custody
    3. Normalizes all forensic CSV / JSON artifacts
    4. Extracts case narrative (FIR text) if present
    5. Persists case data into relational storage and Neo4j case-scoped graph
    6. Returns case_id, entity/artifact counts, and non-fatal warnings
    """
    if not zip_bytes or len(zip_bytes) < 4:
        raise ValueError("Provided file is empty or too small to be a valid ZIP archive.")

    # 1. Validate ZIP format
    try:
        z = zipfile.ZipFile(io.BytesIO(zip_bytes), "r")
    except zipfile.BadZipFile:
        raise ValueError("Corrupt or invalid ZIP archive. File could not be decompressed.")

    # Check zip bomb protection
    total_uncompressed = 0
    infolist = z.infolist()
    if len(infolist) > MAX_FILES_COUNT:
        raise ValueError(f"ZIP archive contains {len(infolist)} files (exceeds {MAX_FILES_COUNT} file safety limit).")

    for info in infolist:
        if info.flag_bits & 0x1:
            raise ValueError(f"Password-protected or encrypted ZIP archive detected ({info.filename}). Unencrypted archive is required.")
        total_uncompressed += info.file_size
        if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
            raise ValueError(
                f"Total uncompressed ZIP size exceeds {MAX_UNCOMPRESSED_BYTES // (1024*1024)}MB limit. Ingestion halted."
            )

    parent_sha256 = generate_sha256(zip_bytes)
    temp_dir = tempfile.mkdtemp(prefix="sih_forensic_zip_")
    base_resolved = Path(temp_dir).resolve()

    warnings: List[str] = []
    file_hashes: Dict[str, str] = {}
    extracted_files: Dict[str, Path] = {}

    try:
        # 2. Safe extraction & pre-hashing
        for member in infolist:
            target_path = (Path(temp_dir) / member.filename).resolve()
            # Zip slip defense
            if not str(target_path).startswith(str(base_resolved)):
                warnings.append(f"Skipped unsafe path traversal file: {member.filename}")
                continue

            if member.is_dir():
                target_path.mkdir(parents=True, exist_ok=True)
                continue

            target_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                with z.open(member) as source, open(target_path, "wb") as target:
                    content = source.read()
                    target.write(content)
            except RuntimeError as e:
                if "password" in str(e).lower() or "encrypted" in str(e).lower():
                    raise ValueError(f"Password-protected file in ZIP archive ({member.filename}). Extraction halted.")
                raise

            f_hash = generate_sha256(content)
            fname_clean = Path(member.filename).name.lower()
            file_hashes[member.filename] = f_hash
            extracted_files[fname_clean] = target_path

        # 3. Read metadata if present
        case_id = (case_id_override or "").strip()
        case_note = ""
        case_title = ""

        if "case_meta.json" in extracted_files:
            try:
                with open(extracted_files["case_meta.json"], "r", encoding="utf-8", errors="ignore") as mf:
                    meta_data = json.load(mf)
                    if not case_id:
                        case_id = str(meta_data.get("case_id") or meta_data.get("id") or "").strip()
                    case_note = str(meta_data.get("note") or meta_data.get("description") or "")
                    case_title = str(meta_data.get("title") or meta_data.get("name") or "")
            except Exception as e:
                warnings.append(f"Failed to parse case_meta.json: {e}")

        if not case_id:
            case_id = f"CASE-{parent_sha256[:8].upper()}"

        case_title = case_title or f"Forensic Investigation {case_id}"
        case_note = case_note or f"Ingested from forensic archive ({parent_sha256[:12]})"

        # 4. Process artifacts
        all_entities: Dict[str, Dict[str, Any]] = {}
        all_artifacts: List[Dict[str, Any]] = []
        recognized_files_count = 0

        # Entities
        if "entities.csv" in extracted_files:
            recognized_files_count += 1
            try:
                with open(extracted_files["entities.csv"], "r", encoding="utf-8", errors="ignore") as f:
                    ents, ent_warns = normalize_entities_csv(f.read())
                    warnings.extend(ent_warns)
                    for e in ents:
                        all_entities[e["entity_id"]] = e
            except Exception as e:
                warnings.append(f"Error reading entities.csv: {e}")

        # Calls
        if "calls.csv" in extracted_files:
            recognized_files_count += 1
            try:
                with open(extracted_files["calls.csv"], "r", encoding="utf-8", errors="ignore") as f:
                    calls, call_warns = normalize_calls_csv(f.read())
                    warnings.extend(call_warns)
                    all_artifacts.extend(calls)
            except Exception as e:
                warnings.append(f"Error reading calls.csv: {e}")

        # Chats
        if "chats.csv" in extracted_files:
            recognized_files_count += 1
            try:
                with open(extracted_files["chats.csv"], "r", encoding="utf-8", errors="ignore") as f:
                    chats, chat_warns = normalize_chats_csv(f.read())
                    warnings.extend(chat_warns)
                    all_artifacts.extend(chats)
            except Exception as e:
                warnings.append(f"Error reading chats.csv: {e}")

        # Files
        if "files.csv" in extracted_files:
            recognized_files_count += 1
            try:
                with open(extracted_files["files.csv"], "r", encoding="utf-8", errors="ignore") as f:
                    files, file_warns = normalize_files_csv(f.read())
                    warnings.extend(file_warns)
                    all_artifacts.extend(files)
            except Exception as e:
                warnings.append(f"Error reading files.csv: {e}")

        # Locations
        if "locations.csv" in extracted_files:
            recognized_files_count += 1
            try:
                with open(extracted_files["locations.csv"], "r", encoding="utf-8", errors="ignore") as f:
                    locs, colocs, loc_warns = normalize_locations_csv(f.read())
                    warnings.extend(loc_warns)
                    all_artifacts.extend(locs)
                    all_artifacts.extend(colocs)
            except Exception as e:
                warnings.append(f"Error reading locations.csv: {e}")

        # Browser history
        if "browser_history.csv" in extracted_files:
            recognized_files_count += 1
            try:
                with open(extracted_files["browser_history.csv"], "r", encoding="utf-8", errors="ignore") as f:
                    browses, browse_warns = normalize_browser_history_csv(f.read())
                    warnings.extend(browse_warns)
                    all_artifacts.extend(browses)
            except Exception as e:
                warnings.append(f"Error reading browser_history.csv: {e}")

        # FIR / Case narrative extraction
        fir_text = ""
        for fir_candidate in ("fir.txt", "fir.docx", "fir.pdf", "narrative.txt", "report.txt"):
            if fir_candidate in extracted_files:
                recognized_files_count += 1
                try:
                    with open(extracted_files[fir_candidate], "rb") as ff:
                        ext_res = extract_document_text(ff.read(), fir_candidate)
                        fir_text = ext_res.get("text", "")
                        # TODO: NLP pipeline for FIR narrative entity and relation extraction
                except Exception as e:
                    warnings.append(f"Error extracting {fir_candidate}: {e}")
                break

        # Check if archive contains forensic data files
        if recognized_files_count == 0 and not all_artifacts and not all_entities:
            raise ValueError("No forensic data files found in archive (expected calls.csv, chats.csv, files.csv, locations.csv, entities.csv, or FIR narrative).")

        # 5. Infer any missing entities from artifact endpoints
        for art in all_artifacts:
            endpoints = [
                art.get("caller_id"), art.get("callee_id"),
                art.get("sender_id"), art.get("receiver_id"),
                art.get("owner_id"), art.get("transferred_to_id"),
                art.get("entity_id"), art.get("entity1"), art.get("entity2")
            ]
            for ep in endpoints:
                if ep and ep not in all_entities and ep != "UNKNOWN":
                    all_entities[ep] = {
                        "entity_id": ep,
                        "name": ep,
                        "phone": ep if ep.replace("+", "").replace("-", "").isdigit() else "",
                        "device_id": "",
                        "ip": ""
                    }

        entities_list = list(all_entities.values())

        # 6. Persist to Database
        # CaseRecord
        case_rec = db.query(CaseRecord).filter(CaseRecord.case_id == case_id).first()
        if not case_rec:
            case_rec = CaseRecord(
                case_id=case_id,
                case_number=case_id,
                title=case_title,
                description=case_note,
                status=CaseStatus.OPEN.value,
                created_by=actor_id
            )
            db.add(case_rec)

        # Log custody
        log_custody_action(
            db=db,
            case_id=case_id,
            action="FORENSIC_ZIP_INGESTED",
            details={
                "case_id": case_id,
                "parent_sha256": parent_sha256,
                "total_files": len(infolist),
                "entities_count": len(entities_list),
                "artifacts_count": len(all_artifacts),
                "file_hashes": file_hashes
            },
            user_id=actor_id,
            role=role,
            source_id=f"ZIP-{parent_sha256[:8]}"
        )

        # EntityLookup (PII encryption)
        for ent in entities_list:
            name = ent.get("name") or ent.get("entity_id")
            hid = generate_hash_id(name)
            existing_lookup = db.query(EntityLookup).filter(EntityLookup.hash_id == hid).first()
            if not existing_lookup:
                enc_name, _ = encrypt_name(name)
                db.add(EntityLookup(hash_id=hid, encrypted_name=enc_name, entity_type="Person"))

        # Store CallRecords
        for art in all_artifacts:
            if art.get("record_type") == "call":
                db.add(CallRecord(
                    call_id=art.get("record_id"),
                    caller=art.get("caller_id", "Unknown"),
                    callee=art.get("callee_id", "Unknown"),
                    duration_sec=art.get("duration_sec", 0),
                    timestamp=art.get("timestamp", ""),
                    case_id=case_id,
                    source_document="calls.csv"
                ))
            elif art.get("record_type") == "chat":
                db.add(ForensicMessage(
                    evidence_id=f"EV-ZIP-{case_id[:8]}",
                    case_id=case_id,
                    sender=art.get("sender_id", "Unknown"),
                    receiver=art.get("receiver_id", "Unknown"),
                    platform=art.get("platform", "Chat"),
                    message_text=art.get("message", ""),
                    timestamp=art.get("timestamp", "")
                ))
            elif art.get("record_type") == "file_artifact":
                db.add(ForensicFile(
                    evidence_id=f"EV-ZIP-{case_id[:8]}",
                    case_id=case_id,
                    filename=art.get("filename", "file.bin"),
                    file_hash=art.get("hash_sha256", "0"*64),
                    sender=art.get("owner_id", "Unknown"),
                    receiver=art.get("transferred_to_id"),
                    timestamp=art.get("timestamp", "")
                ))
            elif art.get("record_type") == "location_ping":
                db.add(ForensicLocation(
                    evidence_id=f"EV-ZIP-{case_id[:8]}",
                    case_id=case_id,
                    person_name=art.get("entity_id", "Unknown"),
                    latitude=art.get("lat", 0.0),
                    longitude=art.get("lng", 0.0),
                    timestamp=art.get("timestamp", "")
                ))

        # Store FIR DocumentRecord if present
        if fir_text:
            db.add(DocumentRecord(
                document_id=f"FIR-{case_id}",
                document_type="FIR",
                text=fir_text,
                case_id=case_id,
                metadata_json={"source": "zip_upload", "hash": file_hashes.get("fir.txt", "")}
            ))

        db.commit()

        # 7. Load into Neo4j and NetworkX
        case_data_payload = {
            "case_id": case_id,
            "note": case_note,
            "entities": entities_list,
            "artifacts": all_artifacts
        }
        graph_res = neo4j_engine.load_case(case_data_payload)

        return {
            "status": "SUCCESS",
            "case_id": case_id,
            "title": case_title,
            "entity_count": len(entities_list),
            "artifact_count": len(all_artifacts),
            "parent_sha256": parent_sha256,
            "file_hashes": file_hashes,
            "warnings": warnings,
            "graph_delta": graph_res,
            "has_fir_text": bool(fir_text)
        }

    finally:
        # 8. Guaranteed temporary directory cleanup
        shutil.rmtree(temp_dir, ignore_errors=True)
