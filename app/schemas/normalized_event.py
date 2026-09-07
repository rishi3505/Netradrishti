from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
from uuid import UUID
from .event import UnifiedSecurityEvent
from .entity import EntityResolutionResult

class NormalizationMetadata(BaseModel):
    status: str = "pending" # pending, normalized, normalized_with_warnings, failed
    version: str = "1.0"
    normalized_at: Optional[datetime] = None
    warnings: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)

class NormalizedEvent(BaseModel):
    event: UnifiedSecurityEvent
    normalization: NormalizationMetadata = Field(default_factory=NormalizationMetadata)
    entities: List[EntityResolutionResult] = Field(default_factory=list)
