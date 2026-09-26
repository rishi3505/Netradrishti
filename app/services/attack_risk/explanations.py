from typing import List
from app.schemas.attack_graph import RiskFactor, AttackPath

def generate_explanation(factors: List[RiskFactor], paths: List[AttackPath]) -> str:
    explanation_parts = []
    
    # Analyze factors
    high_contrib_factors = [f for f in factors if f.contribution > 15]
    if high_contrib_factors:
        explanation_parts.append("Risk increased due to: " + ", ".join(f.reason.lower().strip('.') for f in high_contrib_factors) + ".")
    else:
        explanation_parts.append("Risk is driven by baseline indicator levels.")
        
    # Analyze paths
    if paths:
        explanation_parts.append(f"Identified {len(paths)} potential attack path(s) based on temporal and entity correlation of evidence.")
    else:
        explanation_parts.append("No definitive attack paths could be reconstructed from current evidence.")
        
    return " ".join(explanation_parts)
