from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from app.schemas.common import Severity

class CorrelationRuleConfig(BaseModel):
    enabled: bool = True
    window_minutes: int = 15
    severity_override: Optional[Severity] = None
    custom_params: Dict[str, Any] = Field(default_factory=dict)

class CorrelationRuleSchema(BaseModel):
    rule_id: str
    rule_name: str
    description: str
    enabled: bool
    severity: Severity
    mitre_mapping: List[str] = Field(default_factory=list)
    config: CorrelationRuleConfig

class CorrelationRuleUpdate(BaseModel):
    enabled: Optional[bool] = None
    window_minutes: Optional[int] = None
    severity_override: Optional[Severity] = None
    custom_params: Optional[Dict[str, Any]] = None
