import uuid
from sqlalchemy import Column, String, DateTime, func, JSON, text
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class DBUnifiedSecurityEvent(Base):
    __tablename__ = "security_events"

    event_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp = Column(DateTime(timezone=True), index=True, nullable=False)
    ingestion_timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    source_type = Column(String, index=True, nullable=False)
    event_category = Column(String, index=True, nullable=False)
    event_type = Column(String, index=True, nullable=False)
    severity = Column(String, index=True, nullable=True)
    raw_event = Column(JSONB, nullable=False)
    normalized_event = Column(JSONB, nullable=False)

class DBSecuritySignal(Base):
    __tablename__ = "security_signals"

    signal_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    signal_type = Column(String, index=True, nullable=False)
    detection_method = Column(String, index=True, nullable=False)
    severity = Column(String, index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    signal_data = Column(JSONB, nullable=False)

class DBIncident(Base):
    __tablename__ = "incidents"

    incident_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String, nullable=False)
    status = Column(String, index=True, nullable=False)
    severity = Column(String, index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    incident_data = Column(JSONB, nullable=False)

class DBEntity(Base):
    __tablename__ = "entities"

    entity_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_type = Column(String, index=True, nullable=False)
    first_seen = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    entity_data = Column(JSONB, nullable=False)

class DBThreatIntelligence(Base):
    __tablename__ = "threat_intelligence"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    indicator = Column(String, index=True, nullable=False)
    normalized_indicator = Column(String, index=True, nullable=False)
    indicator_type = Column(String, index=True, nullable=False)
    verdict = Column(String, index=True, nullable=False)
    confidence = Column(JSONB, nullable=False) # store integer or complex object
    provider = Column(String, index=True, nullable=False)
    checked_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    intelligence_data = Column(JSONB, nullable=False)

class DBIncidentIntelligence(Base):
    __tablename__ = "incident_intelligence"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True), index=True, nullable=False)
    threat_intel_id = Column(UUID(as_uuid=True), index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

