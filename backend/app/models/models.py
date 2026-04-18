from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, ForeignKey, Enum as SAEnum, Index, Uuid
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
import enum
from app.database import Base


class UserRole(str, enum.Enum):
    user = "user"
    analyst = "analyst"
    admin = "admin"


class ScanType(str, enum.Enum):
    url = "url"
    message = "message"
    file = "file"


class ScanLabel(str, enum.Enum):
    safe = "SAFE"
    phishing = "PHISHING"
    fraud = "FRAUD"
    suspicious = "SUSPICIOUS"


class User(Base):
    __tablename__ = "users"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    terms_accepted = Column(Boolean, default=False)
    role = Column(SAEnum(UserRole, name="userrole", create_type=False), default=UserRole.user)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)

    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    files = relationship("FileUpload", back_populates="user", cascade="all, delete-orphan")
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id = Column(Uuid, ForeignKey("users.id"), nullable=False)
    scan_type = Column(SAEnum(ScanType), nullable=False)
    input_data = Column(Text, nullable=False)  # URL / message / file reference
    label = Column(SAEnum(ScanLabel), nullable=False)
    confidence = Column(Float, nullable=False)
    reasons = Column(Text, nullable=True)  # JSON array as string
    detection_mode = Column(String(50), nullable=True)
    rule_score = Column(Float, nullable=True)
    final_score = Column(Float, nullable=True)
    language = Column(String(20), nullable=True)
    api_used = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="scans")


class FileUpload(Base):
    __tablename__ = "file_uploads"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id = Column(Uuid, ForeignKey("users.id"), nullable=False)
    original_filename = Column(String(255), nullable=False)
    stored_filename = Column(String(255), nullable=False)  # encrypted on disk
    file_size = Column(Integer, nullable=False)
    mime_type = Column(String(100), nullable=False)
    encryption_iv = Column(String(64), nullable=False)  # AES-256 IV
    scan_status = Column(String(50), default="pending")  # pending/processing/done/error
    progress = Column(Integer, default=0)                # 0 to 100
    status_message = Column(String(255), nullable=True)
    urls_found = Column(Integer, default=0)
    messages_found = Column(Integer, default=0)
    threats_found = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    scanned_at = Column(DateTime(timezone=True), nullable=True)

    user = relationship("User", back_populates="files")


class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id = Column(Uuid, ForeignKey("users.id"), nullable=False)
    key_hash = Column(String(255), nullable=False, unique=True)
    name = Column(String(100), nullable=False)
    is_active = Column(Boolean, default=True)
    scans_used = Column(Integer, default=0)
    last_used = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)

    user = relationship("User", back_populates="api_keys")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id = Column(Uuid, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False)
    resource = Column(String(100), nullable=True)
    resource_id = Column(String(100), nullable=True) # Kept as string to match your audit.py logic!
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    details = Column(Text, nullable=True)  # JSON
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="audit_logs")


class ThreatFeed(Base):
    __tablename__ = "threat_feeds"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    domain = Column(String(255), unique=True, nullable=False, index=True)
    source = Column(String(100), nullable=False)
    last_seen = Column(DateTime(timezone=True), server_default=func.now())