from typing import List
from uuid import uuid4
from datetime import datetime
from app.schemas.threat_intel import ThreatIntelligenceResult, ThreatVerdict

def aggregate_results(results: List[ThreatIntelligenceResult], indicator: str, normalized: str, indicator_type) -> ThreatIntelligenceResult:
    if not results:
        return ThreatIntelligenceResult(
            id=uuid4(),
            indicator=indicator,
            normalized_indicator=normalized,
            indicator_type=indicator_type,
            verdict=ThreatVerdict.UNKNOWN,
            confidence=0,
            provider="aggregator",
            checked_at=datetime.utcnow()
        )
        
    if len(results) == 1:
        return results[0]
        
    # Multi-provider aggregation logic
    highest_verdict_weight = 0
    verdict_map = {
        ThreatVerdict.UNKNOWN: 0,
        ThreatVerdict.BENIGN: 1,
        ThreatVerdict.SUSPICIOUS: 2,
        ThreatVerdict.MALICIOUS: 3
    }
    
    final_verdict = ThreatVerdict.UNKNOWN
    max_confidence = 0
    all_categories = set()
    
    for r in results:
        weight = verdict_map.get(r.verdict, 0)
        if weight > highest_verdict_weight:
            highest_verdict_weight = weight
            final_verdict = r.verdict
        
        # Simple confidence aggregation: take the max for the winning verdict type
        if r.verdict == final_verdict and r.confidence > max_confidence:
            max_confidence = r.confidence
            
        all_categories.update(r.categories)
        
    return ThreatIntelligenceResult(
        id=uuid4(),
        indicator=indicator,
        normalized_indicator=normalized,
        indicator_type=indicator_type,
        verdict=final_verdict,
        confidence=max_confidence, # Could be improved with Bayesian aggregation
        provider="aggregated",
        categories=list(all_categories),
        checked_at=datetime.utcnow()
    )
