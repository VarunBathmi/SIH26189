import os
import re
import json
import zipfile
import xml.etree.ElementTree as ET
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)

def extract_text_from_txt(file_bytes: bytes) -> str:
    """Extract and normalize plain text from bytes with encoding fallbacks."""
    for encoding in ("utf-8", "latin-1", "cp1252", "utf-16"):
        try:
            return file_bytes.decode(encoding).replace("\r\n", "\n")
        except UnicodeDecodeError:
            continue
    return file_bytes.decode("utf-8", errors="ignore").replace("\r\n", "\n")

def extract_text_from_docx_bytes(file_bytes: bytes) -> str:
    """
    Extract text paragraphs and tables from DOCX binary bytes without external heavy libraries
    using standard Python zipfile and XML ElementTree parsing.
    """
    import io
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as docx_zip:
            if "word/document.xml" not in docx_zip.namelist():
                return ""
            xml_content = docx_zip.read("word/document.xml")
            tree = ET.fromstring(xml_content)
            
            # Namespaces used in WordprocessingML
            ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
            
            paragraphs = []
            for p in tree.findall(".//w:p", ns):
                texts = [node.text for node in p.findall(".//w:t", ns) if node.text]
                if texts:
                    paragraphs.append("".join(texts))
            return "\n\n".join(paragraphs)
    except Exception as e:
        logger.warning(f"Failed to parse DOCX bytes: {e}")
        return ""

def extract_text_from_pdf_bytes(file_bytes: bytes) -> Tuple[str, bool]:
    """
    Extract machine-readable text from PDF bytes.
    Returns: (extracted_text, requires_ocr)
    If the PDF is image-only/scanned and has no text stream, requires_ocr is True.
    """
    text = ""
    # Try pypdf if available
    try:
        import pypdf
        import io
        reader = pypdf.PdfReader(io.BytesIO(file_bytes))
        pages_text = []
        for page in reader.pages:
            t = page.extract_text() or ""
            if t.strip():
                pages_text.append(t)
        text = "\n\n".join(pages_text)
    except Exception:
        # Standard fallback: stream string extraction for searchable PDF text
        try:
            raw = file_bytes.decode("latin-1", errors="ignore")
            # Extract literal text between parentheses in BT...ET text objects
            bt_et_blocks = re.findall(r"BT\s*(.*?)\s*ET", raw, re.DOTALL)
            extracted_pieces = []
            for block in bt_et_blocks:
                strings = re.findall(r"\((.*?)\)\s*T[jJ]", block)
                if strings:
                    extracted_pieces.append(" ".join(strings))
            text = "\n".join(extracted_pieces)
        except Exception as e:
            logger.warning(f"PDF extraction fallback error: {e}")

    clean_text = text.strip()
    requires_ocr = len(clean_text) < 10
    return clean_text, requires_ocr

def extract_text_from_json_dict(data: Any) -> str:
    """
    Extract textual narrative and relevant fields from JSON structured evidence
    while preserving context for NLP processing.
    """
    narrative_fields = [
        "text", "fir_text", "narrative", "description", "note", "report",
        "body", "statement", "complaint", "summary", "details", "message_text"
    ]
    extracted_lines = []

    def _traverse(obj: Any):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k.lower() in narrative_fields and isinstance(v, str) and v.strip():
                    extracted_lines.append(v.strip())
                elif isinstance(v, (dict, list)):
                    _traverse(v)
        elif isinstance(obj, list):
            for item in obj:
                _traverse(item)

    _traverse(data)
    if not extracted_lines:
        # If no explicit narrative fields, format key-value pairs
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, str) and len(v.strip()) > 5:
                    extracted_lines.append(f"{k}: {v.strip()}")
    return "\n\n".join(extracted_lines)

def extract_document_text(
    file_bytes: bytes,
    file_name: str,
    file_type: Optional[str] = None
) -> Dict[str, Any]:
    """
    High-level document text extraction router.
    Supports: TXT, PDF, DOCX, JSON, CSV.
    Returns:
    {
        "text": str,
        "file_name": str,
        "file_type": str,
        "char_count": int,
        "requires_ocr": bool,
        "ocr_message": Optional[str]
    }
    """
    ext = (file_type or Path(file_name).suffix.lstrip(".").upper()).upper()
    text = ""
    requires_ocr = False
    ocr_message = None

    if ext in ("TXT", "TEXT", "LOG", "NARRATIVE", "FIR"):
        text = extract_text_from_txt(file_bytes)
    elif ext == "DOCX":
        text = extract_text_from_docx_bytes(file_bytes)
        if not text:
            requires_ocr = False
            ocr_message = "Document is empty or formatted without standard Word text runs."
    elif ext == "PDF":
        text, requires_ocr = extract_text_from_pdf_bytes(file_bytes)
        if requires_ocr:
            ocr_message = (
                "Scanned or image-only PDF detected. Machine-readable text stream is absent. "
                "Optical Character Recognition (OCR engine integration e.g. Tesseract) is required to parse images."
            )
    elif ext == "JSON":
        try:
            raw_str = extract_text_from_txt(file_bytes)
            parsed_json = json.loads(raw_str)
            text = extract_text_from_json_dict(parsed_json)
        except Exception as e:
            text = extract_text_from_txt(file_bytes)
    elif ext in ("CSV", "TSV"):
        text = extract_text_from_txt(file_bytes)
    else:
        text = extract_text_from_txt(file_bytes)

    return {
        "text": text.strip(),
        "file_name": file_name,
        "file_type": ext,
        "char_count": len(text.strip()),
        "requires_ocr": requires_ocr,
        "ocr_message": ocr_message
    }
