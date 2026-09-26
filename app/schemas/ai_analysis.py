from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime
from uuid import UUID, uuid4

class AIAnalysisStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

class AIAnalysisFindingType(str, Enum):
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    POSSIBLE = "POSSIBLE"
    UNKNOWN = "UNKNOWN"

class AIRecommendationCategory(str, Enum):
    INVESTIGATE = "INVESTIGATE"
    CONTAINMENT_CONSIDERATION = "CONTAINMENT_CONSIDERATION"
    EVIDENCE_COLLECTION = "EVIDENCE_COLLECTION"
    RECOVERY_CONSIDERATION = "RECOVERY_CONSIDERATION"
    PREVENTION = "PREVENTION"

class AIAnalysisFinding(BaseModel):
    statement: str
    type: AIAnalysisFindingType
    confidence: int = Field(..., ge=0, le=100)
    evidence_refs: List[str] = Field(default_factory=list)

class AIAnalysisRecommendation(BaseModel):
    category: AIRecommendationCategory
    recommendation: str
    reason: str
    evidence_refs: List[str] = Field(default_factory=list)

class AIAnalysisMissingEvidence(BaseModel):
    item: str
    reason: str

class AIAnalysisTechnique(BaseModel):
    technique_id: str
    name: str
    evidence_refs: List[str] = Field(default_factory=list)

class AIAnalysisAssessment(BaseModel):
    statement: str
    confidence: int = Field(..., ge=0, le=100)

class AIAnalysisResult(BaseModel):
    summary: str
    assessment: AIAnalysisAssessment
    observations: List[AIAnalysisFinding] = Field(default_factory=list)
    inferences: List[AIAnalysisFinding] = Field(default_factory=list)
    possible_scenarios: List[AIAnalysisFinding] = Field(default_factory=list)
    techniques: List[AIAnalysisTechnique] = Field(default_factory=list)
    important_entities: List[str] = Field(default_factory=list)
    important_indicators: List[str] = Field(default_factory=list)
    investigation_questions: List[str] = Field(default_factory=list)
    recommendations: List[AIAnalysisRecommendation] = Field(default_factory=list)
    missing_evidence: List[AIAnalysisMissingEvidence] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)

class AIAnalysisRecord(BaseModel):
    analysis_id: UUID = Field(default_factory=uuid4)
    incident_id: str
    provider: str
    model: str
    prompt_version: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    context_hash: str
    status: AIAnalysisStatus = AIAnalysisStatus.PENDING
    result: Optional[AIAnalysisResult] = None
    error_info: Optional[str] = None

class AIProviderConfig(BaseModel):
    enabled: bool = True
    provider_name: str
    model_name: str
    timeout: int = 30
    max_tokens: int = 2000
    external_transmission_enabled: bool = False
