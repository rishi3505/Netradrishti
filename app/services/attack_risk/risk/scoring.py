from typing import List
from app.schemas.attack_graph import RiskLevel, RiskFactor

def calculate_total_score(factors: List[RiskFactor]) -> int:
    total_score = sum(f.contribution for f in factors)
    return min(100, max(0, int(round(total_score))))

def map_score_to_level(score: int) -> RiskLevel:
    if score < 25:
        return RiskLevel.LOW
    elif score < 50:
        return RiskLevel.MEDIUM
    elif score < 75:
        return RiskLevel.HIGH
    else:
        return RiskLevel.CRITICAL
