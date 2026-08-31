from pydantic import BaseModel, Field
from typing import Optional, List, Any
from datetime import datetime
from uuid import UUID, uuid4
from enum import Enum
from .common import Severity, MitreContext

class DetectionMethod(str, Enum):
    RULE_BASED = "rule_based"
    BEHAVIORAL = "behavioral"
    ANOMALY_DETECTION = "anomaly_detection"
    THREAT_INTELLIGENCE = "threat_intelligence"
    SEQUENCE_DETECTION = "sequence_detection"
    EXTERNAL_SOURCE = "external_source"

class SecuritySignal(BaseModel):
    signal_id: UUID = Field(default_factory=uuid4)
    related_event_ids: List[UUID] = Field(default_factory=list)
    signal_type: str
    detection_method: DetectionMethod
    detection_rule_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: Severity
    confidence: Optional[int] = Field(None, ge=0, le=100)
    risk_score: Optional[int] = Field(None, ge=0, le=100)
    affected_entities: List[str] = Field(default_factory=list)
    mitre_mapping: List[MitreContext] = Field(default_factory=list)
    evidence: Any = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
