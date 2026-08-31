from pydantic import BaseModel, Field
from typing import Optional, Any, Dict
from datetime import datetime
from uuid import UUID, uuid4
from enum import Enum
from .common import (
    NetworkInfo, HostInfo, UserInfo, ProcessInfo, FileInfo, 
    WebInfo, CloudInfo, SecurityContext
)

class EventLifecycle(str, Enum):
    RECEIVED = "RECEIVED"
    VALIDATED = "VALIDATED"
    NORMALIZED = "NORMALIZED"
    ENRICHED = "ENRICHED"
    STORED = "STORED"
    AVAILABLE_FOR_ANALYSIS = "AVAILABLE_FOR_ANALYSIS"
    DETECTED = "DETECTED"
    CORRELATED = "CORRELATED"
    ENRICHED_WITH_THREAT_INTEL = "ENRICHED_WITH_THREAT_INTEL"
    INCIDENT_CREATED = "INCIDENT_CREATED"

class EventIdentity(BaseModel):
    event_id: UUID = Field(default_factory=uuid4)
    event_version: str = "1.0"
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    ingestion_timestamp: datetime = Field(default_factory=datetime.utcnow)
    correlation_id: Optional[UUID] = None
    parent_event_id: Optional[UUID] = None

class EventSource(BaseModel):
    source_name: str
    source_type: str
    vendor: Optional[str] = None
    product: Optional[str] = None
    product_version: Optional[str] = None
    collector_id: Optional[str] = None

class EventClassification(BaseModel):
    event_category: str
    event_type: str
    event_action: Optional[str] = None
    outcome: Optional[str] = None

class RawEvent(BaseModel):
    raw_event: Any
    raw_event_format: str
    source_event_id: Optional[str] = None
    source_timestamp: Optional[datetime] = None

class UnifiedSecurityEvent(BaseModel):
    identity: EventIdentity = Field(default_factory=EventIdentity)
    source: EventSource
    classification: EventClassification
    
    network: Optional[NetworkInfo] = None
    source_host: Optional[HostInfo] = None
    destination_host: Optional[HostInfo] = None
    user: Optional[UserInfo] = None
    process: Optional[ProcessInfo] = None
    file: Optional[FileInfo] = None
    web: Optional[WebInfo] = None
    cloud: Optional[CloudInfo] = None
    
    security_context: Optional[SecurityContext] = None
    raw: RawEvent
    
    lifecycle: EventLifecycle = EventLifecycle.RECEIVED
    custom_fields: Dict[str, Any] = Field(default_factory=dict)
