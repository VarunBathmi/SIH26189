import os
import io
import zipfile
import logging
from pathlib import Path
from typing import Dict, List, Any, Tuple
from app.evidence.hash_engine import generate_sha256

logger = logging.getLogger(__name__)

# Safety limits for ZIP ingestion
MAX_TOTAL_EXTRACTED_SIZE = 100 * 1024 * 1024 # 100 MB
MAX_FILES_COUNT = 500

def check_case_provenance(target_case_id: str, parsed_records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Provenance verification:
    Compares embedded case_ids inside forensic evidence records against the target case_id.
    Warns if an evidence artifact was extracted under a different investigation ID.
    """
    found_case_ids = set()
    for rec in parsed_records:
        rec_data = rec.get("record", {}) if isinstance(rec.get("record"), dict) else rec
        cid = rec_data.get("case_id") or rec_data.get("caseNumber")
        if cid:
            found_case_ids.add(str(cid).strip())

    found_list = list(found_case_ids)
    if not found_list:
        return {
            "case_id_match": True,
            "expected": target_case_id,
            "found": [],
            "warning": None
        }

    is_match = (len(found_list) == 1 and found_list[0] == target_case_id)
    warning = None if is_match else f"Evidence case ID mismatch: Expected '{target_case_id}', but artifact records contain {found_list}"

    return {
        "case_id_match": is_match,
        "expected": target_case_id,
        "found": found_list,
        "warning": warning
    }

def analyze_and_extract_zip(
    zip_bytes: bytes,
    target_extract_dir: Path
) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Safely unpack a forensic evidence ZIP archive:
    1. Computes SHA-256 for the parent ZIP file
    2. Defends against zip bombs (file count & total decompressed size limits)
    3. Defends against directory traversal (Zip Slip vulnerability)
    4. Computes individual SHA-256 for every extracted child artifact
    Returns: (parent_zip_sha256, list_of_extracted_artifacts)
    """
    parent_sha256 = generate_sha256(zip_bytes)
    extracted_artifacts: List[Dict[str, Any]] = []

    target_extract_dir.mkdir(parents=True, exist_ok=True)
    base_resolved = target_extract_dir.resolve()

    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as z:
        # Check zip bomb protection
        total_size = 0
        file_count = len(z.infolist())

        if file_count > MAX_FILES_COUNT:
            raise ValueError(f"ZIP archive contains too many files ({file_count} > {MAX_FILES_COUNT}). Potential Zip Bomb.")

        for info in z.infolist():
            total_size += info.file_size
            if total_size > MAX_TOTAL_EXTRACTED_SIZE:
                raise ValueError(f"Extracted size exceeds {MAX_TOTAL_EXTRACTED_SIZE // (1024*1024)}MB limit. Extraction halted.")

        # Safe extraction
        for member in z.infolist():
            # Check for path traversal
            target_path = (target_extract_dir / member.filename).resolve()
            if not str(target_path).startswith(str(base_resolved)):
                logger.warning(f"Prevented directory traversal attempt: {member.filename}")
                continue

            if member.is_dir():
                target_path.mkdir(parents=True, exist_ok=True)
                continue

            target_path.parent.mkdir(parents=True, exist_ok=True)
            with z.open(member) as source, open(target_path, "wb") as target:
                file_content = source.read()
                target.write(file_content)

            child_sha256 = generate_sha256(file_content)
            extracted_artifacts.append({
                "filename": member.filename,
                "local_path": str(target_path),
                "size_bytes": len(file_content),
                "sha256_hash": child_sha256
            })

    return parent_sha256, extracted_artifacts
