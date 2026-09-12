from app.schemas.incident import Incident, Severity
from app.schemas.signal import SecuritySignal
from typing import List

class IncidentScorer:
    """
    Deterministic scoring for correlated incidents.
    """
    @staticmethod
    def calculate_confidence(signals: List[SecuritySignal], rules_matched: List[str]) -> int:
        base = 50
        
        # More signals = higher confidence
        if len(signals) > 1:
            base += min(len(signals) * 5, 25)
            
        # If signals come from multiple different detection rules, higher confidence
        unique_rules = set(sig.detection_rule_id for sig in signals if sig.detection_rule_id)
        if len(unique_rules) > 1:
            base += min(len(unique_rules) * 5, 15)
            
        # If signals themselves have high confidence
        high_conf_signals = [s for s in signals if s.confidence and s.confidence >= 80]
        if high_conf_signals:
            base += 10
            
        return min(max(base, 0), 100)

    @staticmethod
    def calculate_severity(signals: List[SecuritySignal]) -> Severity:
        """
        Derives incident severity from the highest severity signal.
        """
        has_critical = any(sig.severity == Severity.CRITICAL for sig in signals)
        if has_critical:
            return Severity.CRITICAL
            
        has_high = any(sig.severity == Severity.HIGH for sig in signals)
        if has_high:
            return Severity.HIGH
            
        has_medium = any(sig.severity == Severity.MEDIUM for sig in signals)
        if has_medium:
            return Severity.MEDIUM
            
        has_low = any(sig.severity == Severity.LOW for sig in signals)
        if has_low:
            return Severity.LOW
            
        return Severity.INFO
