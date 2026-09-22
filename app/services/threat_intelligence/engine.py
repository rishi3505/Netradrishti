from typing import List, Dict, Any, Optional
from uuid import uuid4
from datetime import datetime
import asyncio
from app.schemas.threat_intel import (
    ThreatIntelligenceRequest,
    ThreatIntelligenceResult,
    ThreatVerdict
)
from app.services.threat_intelligence.normalizer import identify_and_normalize
from app.services.threat_intelligence.cache import ti_cache
from app.services.threat_intelligence.registry import registry
from app.services.threat_intelligence.scoring import aggregate_results
from app.core.config import settings

class ThreatIntelligenceEngine:
    async def process_indicator(self, request: ThreatIntelligenceRequest) -> ThreatIntelligenceResult:
        if not settings.THREAT_INTEL_ENABLED:
            return self._unknown_result(request)
            
        # 1. Normalize
        ind_type, normalized = identify_and_normalize(request.indicator)
        if not ind_type:
            # Cannot normalize, return unknown
            return self._unknown_result(request)
            
        # Update request with identified type
        request.indicator_type = ind_type
            
        # 2. Get enabled providers
        providers = registry.get_enabled_providers()
        if not providers:
            return self._unknown_result(request)
            
        provider_results = []
        
        # 3. Lookup across providers with cache
        for provider in providers:
            cached_result = ti_cache.get(ind_type.value, normalized, provider.name)
            if cached_result:
                provider_results.append(cached_result)
            else:
                try:
                    # Could use gather for parallel execution here
                    result = await provider.lookup(request, normalized)
                    ti_cache.set(result)
                    provider_results.append(result)
                except Exception as e:
                    # Log failure, continue with other providers
                    pass
                    
        # 4. Aggregate
        return aggregate_results(provider_results, request.indicator, normalized, ind_type)
        
    async def process_batch(self, requests: List[ThreatIntelligenceRequest]) -> List[ThreatIntelligenceResult]:
        # Simple batch implementation, could be optimized with provider batch APIs
        tasks = [self.process_indicator(req) for req in requests]
        return await asyncio.gather(*tasks)

    def _unknown_result(self, request: ThreatIntelligenceRequest) -> ThreatIntelligenceResult:
        return ThreatIntelligenceResult(
            id=uuid4(),
            indicator=request.indicator,
            normalized_indicator=request.indicator,
            indicator_type=request.indicator_type, # Might be None
            verdict=ThreatVerdict.UNKNOWN,
            confidence=0,
            provider="system",
            checked_at=datetime.utcnow()
        )

engine = ThreatIntelligenceEngine()
