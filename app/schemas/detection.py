from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from app.schemas.common import Severity

class DetectionRuleConfig(BaseModel):
    enabled: bool = True
    threshold: Optional[int] = None
    window_minutes: Optional[int] = None
    severity: Optional[Severity] = None
    custom_params: Dict[str, Any] = Field(default_factory=dict)

class DetectionRuleSchema(BaseModel):
    rule_id: str
    rule_name: str
    description: str
    version: str
    enabled: bool
    severity: Severity
    category: str
    mitre_mapping: List[str] = Field(default_factory=list)
    detection_type: str
    config: DetectionRuleConfig

class DetectionRuleUpdate(BaseModel):
    enabled: Optional[bool] = None
    threshold: Optional[int] = None
    window_minutes: Optional[int] = None
    severity: Optional[Severity] = None
    custom_params: Optional[Dict[str, Any]] = None

class DetectionStatus(BaseModel):
    engine_status: str
    active_rules: int
    total_signals_generated: int
    last_run: Optional[datetime] = None
