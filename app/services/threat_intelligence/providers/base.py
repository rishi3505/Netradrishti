from abc import ABC, abstractmethod
from typing import List, Optional
from app.schemas.threat_intel import (
    ThreatIntelligenceResult, 
    ThreatIntelligenceRequest,
    ProviderHealthStatus
)

class ThreatIntelligenceProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass
        
    @property
    @abstractmethod
    def reliability(self) -> int:
        pass

    @abstractmethod
    async def lookup(self, request: ThreatIntelligenceRequest, normalized_indicator: str) -> ThreatIntelligenceResult:
        pass
        
    @abstractmethod
    async def lookup_batch(self, requests: List[ThreatIntelligenceRequest], normalized_indicators: List[str]) -> List[ThreatIntelligenceResult]:
        pass
        
    @abstractmethod
    async def health_check(self) -> ProviderHealthStatus:
        pass
