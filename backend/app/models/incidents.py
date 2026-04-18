"""
Incident Model — Security Incident Tracking
============================================
Stores detected security incidents when dangerous domains are found.
Lifecycle: open → investigating → resolved / false_positive
"""

from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, Enum as SAEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid
import enum
from app.database import Base


class IncidentSeverity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class IncidentStatus(str, enum.Enum):
    open = "open"
    investigating = "investigating"
    resolved = "resolved"
    false_positive = "false_positive"


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    # What was detected
    domain = Column(String(255), nullable=False, index=True)
    ip = Column(String(45), nullable=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String(20), nullable=True)
    process = Column(String(100), nullable=True)

    # Severity
    severity = Column(
        SAEnum(IncidentSeverity, name="incidentseverity", create_type=False),
        nullable=False,
        default=IncidentSeverity.medium,
    )

    # Analysis
    confidence = Column(Float, nullable=False, default=0.0)
    risk_score = Column(Integer, nullable=False, default=0)
    description = Column(Text, nullable=True)
    indicators = Column(Text, nullable=True)  # JSON array

    # Tracking
    status = Column(
        SAEnum(IncidentStatus, name="incidentstatus", create_type=False),
        nullable=False,
        default=IncidentStatus.open,
    )
    resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    notes = Column(Text, nullable=True)

    # Source
    data_source = Column(String(20), default="real")  # real or simulated

    # Auto-created from network monitoring
    auto_created = Column(Boolean, default=True)
