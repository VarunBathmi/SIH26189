import re
import logging
from typing import Dict, List, Any
import spacy
from rapidfuzz import fuzz

logger = logging.getLogger(__name__)

# Load SpaCy model (Transformer preferred, fallback to Small)
_nlp = None

def get_spacy_model():
    global _nlp
    if _nlp is None:
        try:
            _nlp = spacy.load("en_core_web_trf")
            logger.info("Loaded spaCy transformer model (en_core_web_trf).")
        except Exception:
            try:
                _nlp = spacy.load("en_core_web_sm")
                logger.info("Loaded spaCy fallback model (en_core_web_sm).")
            except Exception as e:
                logger.error(f"Failed to load any spaCy model: {e}")
                _nlp = spacy.blank("en")
    return _nlp

# Regex definitions for Indian phone numbers, vehicles, and currency
PHONE_REGEX = re.compile(r"\b(?:\+91[\-\s]?)?[6-9]\d{9}\b")
VEHICLE_REGEX = re.compile(r"\b[A-Z]{2}[-\s]?\d{2}[-\s]?[A-Z]{1,2}[-\s]?\d{4}\b")
CURRENCY_REGEX = re.compile(r"(?:₹|Rs\.?|INR)\s*([0-9,]+(?:\.[0-9]{1,2})?)", re.IGNORECASE)

def deduplicate_entities_fuzzy(entities: List[str], threshold: int = 85) -> List[str]:
    """
    Merge minor name variations or substrings within a document into the longest canonical entity name.
    """
    if not entities:
        return []

    # Sort descending by length so longer specific names come first
    sorted_ents = sorted(list(set(entities)), key=len, reverse=True)
    canonical = []

    for ent in sorted_ents:
        match_found = False
        for c in canonical:
            if fuzz.ratio(ent.lower(), c.lower()) >= threshold or ent.lower() in c.lower():
                match_found = True
                break
        if not match_found:
            canonical.append(ent)

    return canonical

def extract_entities(text: str) -> Dict[str, List[str]]:
    """
    Extract structured entities from raw unstructured investigation text:
    - PERSON: Suspects and associates
    - LOCATION: GPE, FAC, LOC
    - ORGANIZATION: ORG (corporations, gangs, banks)
    - PHONE: Indian mobile format
    - VEHICLE: Registration plate format
    - MONEY: Currency values
    - DATE: Calendar dates
    - TIME: Clock times
    """
    if not text:
        return {
            "PERSON": [],
            "LOCATION": [],
            "ORGANIZATION": [],
            "PHONE": [],
            "VEHICLE": [],
            "MONEY": [],
            "DATE": [],
            "TIME": []
        }

    nlp = get_spacy_model()
    doc = nlp(text)

    persons = []
    locations = []
    organizations = []
    money = []
    dates = []
    times = []

    for ent in doc.ents:
        cleaned = ent.text.strip()
        if not cleaned:
            continue
        if ent.label_ == "PERSON":
            persons.append(cleaned)
        elif ent.label_ in ("GPE", "LOC", "FAC"):
            locations.append(cleaned)
        elif ent.label_ == "ORG":
            organizations.append(cleaned)
        elif ent.label_ == "MONEY":
            money.append(cleaned)
        elif ent.label_ == "DATE":
            dates.append(cleaned)
        elif ent.label_ == "TIME":
            times.append(cleaned)

    # Regex extractions
    phones = PHONE_REGEX.findall(text)
    vehicles = VEHICLE_REGEX.findall(text)

    # Additional currency regex match
    for curr_match in CURRENCY_REGEX.finditer(text):
        full_curr = curr_match.group(0).strip()
        if full_curr not in money:
            money.append(full_curr)

    # Fuzzy intra-document deduplication for names and locations
    canonical_persons = deduplicate_entities_fuzzy(persons)
    canonical_locations = deduplicate_entities_fuzzy(locations)
    canonical_orgs = deduplicate_entities_fuzzy(organizations)

    return {
        "PERSON": canonical_persons,
        "LOCATION": canonical_locations,
        "ORGANIZATION": canonical_orgs,
        "PHONE": list(set(phones)),
        "VEHICLE": list(set(vehicles)),
        "MONEY": list(set(money)),
        "DATE": list(set(dates)),
        "TIME": list(set(times))
    }
