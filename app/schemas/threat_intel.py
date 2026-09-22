from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from uuid import UUID, uuid4
from enum import Enum

class ThreatVerdict(str, Enum):
    UNKNOWN = "unknown"
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"

class IndicatorType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"

class ThreatIntelligenceResult(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    indicator: str
    normalized_indicator: str
    indicator_type: Optional[IndicatorType] = None
    verdict: ThreatVerdict = ThreatVerdict.UNKNOWN
    confidence: int = Field(0, ge=0, le=100)
    provider: str
    categories: List[str] = Field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    checked_at: datetime = Field(default_factory=datetime.utcnow)
    source_url: Optional[str] = None
    raw_reference: Optional[Dict[str, Any]] = None

class ThreatIntelligenceRequest(BaseModel):
    indicator: str
    indicator_type: Optional[IndicatorType] = None
    
class BatchThreatIntelligenceRequest(BaseModel):
    indicators: List[str]
    indicator_types: Optional[List[IndicatorType]] = None

class ProviderHealthStatus(BaseModel):
    provider: str
    status: str
    latency_ms: Optional[float] = None
    error: Optional[str] = None
