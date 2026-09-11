import datetime
from sqlalchemy import (
    Column, Integer, String, Text, Float, Boolean, DateTime, JSON, ForeignKey, Enum as SQLEnum, Index
)
from sqlalchemy.orm import relationship
from app.database import Base
import enum

def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)

class UserRole(str, enum.Enum):
    ADMINISTRATOR = "ADMINISTRATOR"
    INVESTIGATOR = "INVESTIGATOR"
    VIEWER = "VIEWER"

class CaseStatus(str, enum.Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    CLOSED = "CLOSED"

class DocumentType(str, enum.Enum):
    FIR = "FIR"
    SOCIAL_MEDIA = "SOCIAL_MEDIA"
    INTEL_REPORT = "INTEL_REPORT"
    SURVEILLANCE = "SURVEILLANCE"

class AlertStatus(str, enum.Enum):
    PENDING = "PENDING"
    CONFIRMED = "CONFIRMED"
    DISMISSED = "DISMISSED"

class RevealStatus(str, enum.Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"

class IntegrityStatus(str, enum.Enum):
    VERIFIED = "VERIFIED"
    COMPROMISED = "COMPROMISED"
    PENDING = "PENDING"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=True)
    role = Column(String(50), default=UserRole.INVESTIGATOR.value, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    otp_code = Column(String(255), nullable=True)
    otp_expires_at = Column(DateTime, nullable=True)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow)

class CaseRecord(Base):
    __tablename__ = "case_records"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String(100), unique=True, index=True, nullable=False)
    case_number = Column(String(100), nullable=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(50), default=CaseStatus.OPEN.value, index=True, nullable=False)
    created_by = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

class DocumentRecord(Base):
    __tablename__ = "document_records"

    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(String(100), index=True, nullable=False)
    document_type = Column(String(50), default=DocumentType.FIR.value, nullable=False)
    text = Column(Text, nullable=False)
    case_id = Column(String(100), index=True, nullable=False)
    metadata_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=utcnow)

class CallRecord(Base):
    __tablename__ = "call_records"

    id = Column(Integer, primary_key=True, index=True)
    call_id = Column(String(100), index=True, nullable=True)
    caller = Column(String(255), nullable=False)
    callee = Column(String(255), nullable=False)
    duration_sec = Column(Integer, default=0)
    timestamp = Column(String(100), nullable=True)
    case_id = Column(String(100), index=True, nullable=False)
    source_document = Column(String(100), nullable=True)
    confidence = Column(String(255), default="extracted_from_text — requires investigator verification")
    created_at = Column(DateTime, default=utcnow)

class TransactionRecord(Base):
    __tablename__ = "transaction_records"

    id = Column(Integer, primary_key=True, index=True)
    transaction_id = Column(String(100), index=True, nullable=True)
    sender = Column(String(255), nullable=False)
    receiver = Column(String(255), nullable=False)
    amount = Column(Float, nullable=False)
    currency = Column(String(20), default="INR")
    timestamp = Column(String(100), nullable=True)
    landmark = Column(String(255), nullable=True)
    area = Column(String(255), nullable=True)
    case_id = Column(String(100), index=True, nullable=False)
    source_document = Column(String(100), nullable=True)
    detection_status = Column(String(100), default="NORMAL")
    created_at = Column(DateTime, default=utcnow)

class PersonMatch(Base):
    __tablename__ = "person_matches"

    id = Column(Integer, primary_key=True, index=True)
    person1 = Column(String(255), nullable=False)
    person2 = Column(String(255), nullable=False)
    matching_score = Column(Float, nullable=False)
    matching_reason = Column(String(255), nullable=False)
    case_id = Column(String(100), index=True, nullable=False)
    created_at = Column(DateTime, default=utcnow)

class EvidenceRecord(Base):
    """
    Professional Digital Evidence record with SHA-256 cryptographic fingerprint,
    visual symbols, verification metadata, and chain-of-custody linkage.
    """
    __tablename__ = "evidence_records"

    id = Column(Integer, primary_key=True, index=True)
    evidence_id = Column(String(100), unique=True, index=True, nullable=False)
    case_id = Column(String(100), index=True, nullable=False)
    file_name = Column(String(255), nullable=False)
    file_type = Column(String(100), nullable=True)
    file_size = Column(Integer, nullable=False) # bytes
    sha256_hash = Column(String(64), nullable=False, index=True)
    hash_algorithm = Column(String(50), default="SHA-256", nullable=False)
    hash_created_at = Column(DateTime, default=utcnow)
    integrity_status = Column(String(50), default=IntegrityStatus.VERIFIED.value, nullable=False)
    storage_path = Column(String(512), nullable=False)
    visual_blocks = Column(Text, nullable=True)
    visual_symbols = Column(Text, nullable=True)
    metadata_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=utcnow)

class ForensicArtifact(Base):
    __tablename__ = "forensic_artifacts"

    id = Column(Integer, primary_key=True, index=True)
    evidence_id = Column(String(100), index=True, nullable=False)
    case_id = Column(String(100), index=True, nullable=False)
    artifact_type = Column(String(50), nullable=False)
    name = Column(String(255), nullable=False)
    sha256_hash = Column(String(64), nullable=False)
    size_bytes = Column(Integer, default=0)
    metadata_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=utcnow)

class ForensicMessage(Base):
    __tablename__ = "forensic_messages"

    id = Column(Integer, primary_key=True, index=True)
    evidence_id = Column(String(100), index=True, nullable=False)
    case_id = Column(String(100), index=True, nullable=False)
    sender = Column(String(255), nullable=False)
    receiver = Column(String(255), nullable=False)
    platform = Column(String(50), default="SMS")
    message_text = Column(Text, nullable=True)
    timestamp = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=utcnow)

class ForensicDevice(Base):
    __tablename__ = "forensic_devices"

    id = Column(Integer, primary_key=True, index=True)
    evidence_id = Column(String(100), index=True, nullable=False)
    case_id = Column(String(100), index=True, nullable=False)
    owner_name = Column(String(255), nullable=True)
    device_model = Column(String(255), nullable=True)
    imei = Column(String(100), nullable=True)
    mac_address = Column(String(100), nullable=True)
    os_version = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=utcnow)

class ForensicFile(Base):
    __tablename__ = "forensic_files"

    id = Column(Integer, primary_key=True, index=True)
    evidence_id = Column(String(100), index=True, nullable=False)
    case_id = Column(String(100), index=True, nullable=False)
    filename = Column(String(255), nullable=False)
    file_hash = Column(String(64), nullable=False)
    sender = Column(String(255), nullable=True)
    receiver = Column(String(255), nullable=True)
    timestamp = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=utcnow)

class ForensicLocation(Base):
    __tablename__ = "forensic_locations"

    id = Column(Integer, primary_key=True, index=True)
    evidence_id = Column(String(100), index=True, nullable=False)
    case_id = Column(String(100), index=True, nullable=False)
    person_name = Column(String(255), nullable=False)
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    timestamp = Column(String(100), nullable=True)
    location_name = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=utcnow)

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String(100), index=True, nullable=False)
    alert_type = Column(String(100), nullable=False) # CALL_BURST, TRANSACTION_PATTERN, CO_LOCATION, HIGH_CENTRALITY, POTENTIAL_MATCH
    related_entities = Column(JSON, nullable=True) # list of hash_ids or names
    source_module = Column(String(100), nullable=False)
    reason = Column(Text, nullable=True)
    detected_at = Column(DateTime, default=utcnow)
    status = Column(String(50), default=AlertStatus.PENDING.value, index=True, nullable=False)
    reviewed_by = Column(String(255), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    review_notes = Column(Text, nullable=True)

class EntityLookup(Base):
    """
    Encrypted PII Storage:
    Public graph only holds hash_id.
    Real name is Fernet-encrypted (AES-128-CBC + HMAC-SHA256) and strictly guarded.
    """
    __tablename__ = "entity_lookup"

    id = Column(Integer, primary_key=True, index=True)
    hash_id = Column(String(64), unique=True, index=True, nullable=False)
    encrypted_name = Column(Text, nullable=False)
    entity_type = Column(String(50), default="Person", nullable=False)
    created_at = Column(DateTime, default=utcnow)

class RevealRequest(Base):
    """
    Dual-Authorization identity reveal state machine.
    Requires approvals from both an ADMINISTRATOR and a distinct INVESTIGATOR.
    """
    __tablename__ = "reveal_requests"

    id = Column(Integer, primary_key=True, index=True)
    hash_id = Column(String(64), index=True, nullable=False)
    case_id = Column(String(100), index=True, nullable=False)
    requested_by = Column(String(255), nullable=False) # user email
    requester_role = Column(String(50), nullable=False)
    reason = Column(Text, nullable=False)
    
    admin_approval = Column(Boolean, nullable=True)
    admin_approved_by = Column(String(255), nullable=True)
    admin_approved_at = Column(DateTime, nullable=True)
    
    investigator_approval = Column(Boolean, nullable=True)
    investigator_approved_by = Column(String(255), nullable=True)
    investigator_approved_at = Column(DateTime, nullable=True)
    
    rejection_reason = Column(Text, nullable=True)
    status = Column(String(50), default=RevealStatus.PENDING.value, index=True, nullable=False)
    created_at = Column(DateTime, default=utcnow)

class AuditLog(Base):
    """
    Append-only security and operational audit ledger.
    No update or delete operations are permitted.
    """
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=utcnow, nullable=False)
    user_id = Column(String(255), nullable=True)
    role = Column(String(50), nullable=True)
    action = Column(String(100), nullable=False)
    resource = Column(String(255), nullable=True)
    status = Column(String(50), default="SUCCESS", nullable=False)
    details = Column(JSON, nullable=True)
    ip_address = Column(String(100), nullable=True)

class CustodyLog(Base):
    """
    Digital Chain of Custody Table maintaining an immutable SHA-256 Hash Chain.
    current_hash = SHA256(case_id + action + canonical_details + previous_hash + created_at)
    Starting from genesis '0' * 64.
    """
    __tablename__ = "custody_log"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String(100), index=True, nullable=False)
    action = Column(String(100), index=True, nullable=False)
    details = Column(JSON, nullable=True)
    previous_hash = Column(String(64), nullable=False)
    current_hash = Column(String(64), nullable=False)
    
    user_id = Column(String(255), nullable=True)
    role = Column(String(50), nullable=True)
    source_id = Column(String(255), nullable=True)
    entity_id = Column(String(255), nullable=True)
    relationship_id = Column(String(255), nullable=True)
    ip_address = Column(String(100), nullable=True)
    request_id = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    __table_args__ = (
        Index("ix_custody_case_id_id", "case_id", "id"),
    )
