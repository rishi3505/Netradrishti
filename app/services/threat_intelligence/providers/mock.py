from typing import List
import time
from datetime import datetime
from uuid import uuid4
from app.schemas.threat_intel import (
    ThreatIntelligenceResult, 
    ThreatIntelligenceRequest,
    ProviderHealthStatus,
    ThreatVerdict
)
from app.services.threat_intelligence.providers.base import ThreatIntelligenceProvider

class MockProvider(ThreatIntelligenceProvider):
    @property
    def name(self) -> str:
        return "mock"
        
    @property
    def reliability(self) -> int:
        return 90

    async def lookup(self, request: ThreatIntelligenceRequest, normalized_indicator: str) -> ThreatIntelligenceResult:
        verdict = ThreatVerdict.UNKNOWN
        confidence = 0
        categories = []
        
        # Deterministic logic for testing
        if "malicious" in normalized_indicator:
            verdict = ThreatVerdict.MALICIOUS
            confidence = 95
            categories = ["malware", "test"]
        elif "suspicious" in normalized_indicator:
            verdict = ThreatVerdict.SUSPICIOUS
            confidence = 60
            categories = ["test"]
        elif "benign" in normalized_indicator:
            verdict = ThreatVerdict.BENIGN
            confidence = 99
            categories = ["clean", "test"]
            
        return ThreatIntelligenceResult(
            id=uuid4(),
            indicator=request.indicator,
            normalized_indicator=normalized_indicator,
            indicator_type=request.indicator_type,
            verdict=verdict,
            confidence=confidence,
            provider=self.name,
            categories=categories,
            checked_at=datetime.utcnow()
        )
        
    async def lookup_batch(self, requests: List[ThreatIntelligenceRequest], normalized_indicators: List[str]) -> List[ThreatIntelligenceResult]:
        results = []
        for req, norm in zip(requests, normalized_indicators):
            results.append(await self.lookup(req, norm))
        return results
        
    async def health_check(self) -> ProviderHealthStatus:
        return ProviderHealthStatus(
            provider=self.name,
            status="healthy",
            latency_ms=1.5
        )
