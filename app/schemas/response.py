from pydantic import BaseModel, Field
from typing import Optional, List, Any
from datetime import datetime
from uuid import UUID, uuid4
from enum import Enum

class ActionStatus(str, Enum):
    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    SIMULATED = "SIMULATED"

class ActionCategory(str, Enum):
    INVESTIGATION = "INVESTIGATION"
    EVIDENCE_COLLECTION = "EVIDENCE_COLLECTION"
    CONTAINMENT = "CONTAINMENT"
    ERADICATION = "ERADICATION"
    MITIGATION = "MITIGATION"
    RECOVERY = "RECOVERY"
    PREVENTION = "PREVENTION"
    LESSONS_LEARNED = "LESSONS_LEARNED"

class Reversibility(str, Enum):
    REVERSIBLE = "REVERSIBLE"
    PARTIALLY_REVERSIBLE = "PARTIALLY_REVERSIBLE"
    IRREVERSIBLE = "IRREVERSIBLE"

class ActionRisk(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"

class ResponseAction(BaseModel):
    action_id: UUID = Field(default_factory=uuid4)
    plan_id: Optional[UUID] = None
    incident_id: UUID
    action_type: str
    category: ActionCategory
    description: str
    rationale: str
    priority: str = "P3"
    risk: ActionRisk = ActionRisk.LOW
    expected_effect: str
    prerequisites: List[str] = Field(default_factory=list)
    evidence_references: List[str] = Field(default_factory=list)
    recommended_by: str = "Netradhrishti"
    approval_required: bool = True
    status: ActionStatus = ActionStatus.PROPOSED
    reversibility: Reversibility = Reversibility.REVERSIBLE
    rollback_considerations: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Audit trail for approvals
    approver_id: Optional[str] = None
    approval_timestamp: Optional[datetime] = None
    approval_reason: Optional[str] = None

class ResponsePlan(BaseModel):
    plan_id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    status: str = "DRAFT"
    priority: str = "HIGH"
    actions: List[ResponseAction] = Field(default_factory=list)
    approval_required: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    def get_actions_by_category(self, category: ActionCategory) -> List[ResponseAction]:
        return [a for a in self.actions if a.category == category]
