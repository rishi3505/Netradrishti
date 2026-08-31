from pydantic import BaseModel, Field
from typing import Optional, List, Any
from datetime import datetime
from uuid import UUID, uuid4
from enum import Enum
from .common import Severity, MitreContext

class IncidentStatus(str, Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"

class Incident(BaseModel):
    incident_id: UUID = Field(default_factory=uuid4)
    title: str
    description: Optional[str] = None
    status: IncidentStatus = IncidentStatus.NEW
    severity: Severity
    priority: Optional[str] = None
    confidence: Optional[int] = Field(None, ge=0, le=100)
    risk_score: Optional[int] = Field(None, ge=0, le=100)
    related_signal_ids: List[UUID] = Field(default_factory=list)
    related_event_ids: List[UUID] = Field(default_factory=list)
    affected_entities: List[str] = Field(default_factory=list)
    attack_stage: Optional[str] = None
    mitre_techniques: List[MitreContext] = Field(default_factory=list)
    timeline: List[Any] = Field(default_factory=list)
    evidence: Any = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
