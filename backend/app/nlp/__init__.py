"""
NLP Entity, Event, Relationship Extraction and Forensic Text Processing Module
SIH 26189 AI-Powered Criminal Network Analysis Platform
"""

from app.nlp.entity_extractor import (
    get_spacy_model,
    extract_entities,
    extract_entities_detailed,
    deduplicate_entities_fuzzy,
    PHONE_REGEX,
    VEHICLE_REGEX,
    CURRENCY_REGEX,
    EMAIL_REGEX,
    IPV4_CANDIDATE_REGEX,
    validate_ip_address
)
from app.nlp.event_extractor import (
    extract_events_from_text,
    parse_duration_seconds,
    parse_numeric_amount
)
from app.nlp.relation_extractor import extract_relationships
from app.nlp.call_detection import detect_suspicious_calls, parse_call_hour
from app.nlp.person_matching import (
    match_person,
    normalize_person_name,
    resolve_case_identities
)
from app.nlp.text_extractor import (
    extract_document_text,
    extract_text_from_txt,
    extract_text_from_docx_bytes,
    extract_text_from_pdf_bytes,
    extract_text_from_json_dict
)

__all__ = [
    "get_spacy_model",
    "extract_entities",
    "extract_entities_detailed",
    "deduplicate_entities_fuzzy",
    "extract_events_from_text",
    "extract_relationships",
    "detect_suspicious_calls",
    "parse_call_hour",
    "match_person",
    "normalize_person_name",
    "resolve_case_identities",
    "extract_document_text",
    "extract_text_from_txt",
    "extract_text_from_docx_bytes",
    "extract_text_from_pdf_bytes",
    "extract_text_from_json_dict",
    "PHONE_REGEX",
    "VEHICLE_REGEX",
    "CURRENCY_REGEX",
    "EMAIL_REGEX",
    "IPV4_CANDIDATE_REGEX",
    "validate_ip_address"
]
