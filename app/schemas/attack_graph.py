from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime
from uuid import UUID, uuid4

class AttackGraphNodeType(str, Enum):
    EVENT = "event"
    SIGNAL = "signal"
    INCIDENT = "incident"
    ENTITY = "entity"
    TECHNIQUE = "technique"
    IOC = "ioc"

class AttackGraphEdgeType(str, Enum):
    RELATED_TO = "related_to"
    CAUSED = "caused"
    OBSERVED_ON = "observed_on"
    ASSOCIATED_WITH = "associated_with"
    AUTHENTICATED_AS = "authenticated_as"
    EXECUTED_BY = "executed_by"
    CONNECTED_TO = "connected_to"
    RESOLVED_TO = "resolved_to"
    INDICATES = "indicates"
    SUPPORTS = "supports"
    PRECEDED = "preceded"
    FOLLOWED_BY = "followed_by"
    USES_TECHNIQUE = "uses_technique"
    ENRICHED_BY = "enriched_by"

class AttackGraphNode(BaseModel):
    node_id: str
    node_type: AttackGraphNodeType
    source_reference: Optional[str] = None
    display_metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class AttackGraphEdge(BaseModel):
    edge_id: UUID = Field(default_factory=uuid4)
    source_node: str
    destination_node: str
    relationship_type: AttackGraphEdgeType
    confidence: int = Field(..., ge=0, le=100)
    timestamp: Optional[datetime] = None
    evidence_references: List[str] = Field(default_factory=list)
    explanation: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class AttackPath(BaseModel):
    path_id: UUID = Field(default_factory=uuid4)
    incident_id: str
    nodes: List[AttackGraphNode]
    edges: List[AttackGraphEdge]
    confidence: int = Field(..., ge=0, le=100)
    explanation: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class RiskFactor(BaseModel):
    factor: str
    value: float
    weight: float
    contribution: float
    reason: str

class RiskAssessment(BaseModel):
    assessment_id: UUID = Field(default_factory=uuid4)
    incident_id: str
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    confidence: int = Field(..., ge=0, le=100)
    factors: List[RiskFactor] = Field(default_factory=list)
    attack_paths: List[AttackPath] = Field(default_factory=list)
    techniques: List[str] = Field(default_factory=list)
    affected_entities: List[str] = Field(default_factory=list)
    evidence_count: int = 0
    model_version: str = "v1"
    calculated_at: datetime = Field(default_factory=datetime.utcnow)
