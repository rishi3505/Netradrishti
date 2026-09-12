from app.schemas.signal import SecuritySignal
from app.detection.rules.base import DetectionRule

class ConfidenceCalculator:
    """
    Calculates a confidence score between 0 and 100 for a generated signal.
    """
    @staticmethod
    def calculate(signal: SecuritySignal, rule: DetectionRule) -> int:
        base_confidence = 50
        
        # Rule strength
        if rule.config.severity == "critical":
            base_confidence += 20
        elif rule.config.severity == "high":
            base_confidence += 15
            
        # Evidence quality (e.g. if threshold is heavily exceeded)
        evidence = signal.evidence or {}
        
        # Example for threshold based rules
        threshold = getattr(rule.config, 'threshold', None)
        if threshold:
            count_keys = [k for k in evidence.keys() if 'count' in k.lower() or 'total' in k.lower()]
            for k in count_keys:
                actual_val = evidence[k]
                if isinstance(actual_val, (int, float)):
                    ratio = actual_val / threshold if threshold > 0 else 1
                    if ratio >= 5:
                        base_confidence += 30
                    elif ratio >= 2:
                        base_confidence += 15
                    elif ratio >= 1.5:
                        base_confidence += 10
                        
        # Multiple entities affected
        if len(signal.affected_entities) > 2:
            base_confidence += 10
            
        return min(max(base_confidence, 0), 100)
