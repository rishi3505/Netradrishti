from app.schemas.signal import SecuritySignal

class RiskCalculator:
    """
    Calculates an initial risk score between 0 and 100 based on severity and confidence.
    """
    @staticmethod
    def calculate(signal: SecuritySignal) -> int:
        severity_weights = {
            "critical": 100,
            "high": 80,
            "medium": 50,
            "low": 20,
            "info": 5
        }
        
        severity_val = severity_weights.get(signal.severity.lower() if isinstance(signal.severity, str) else signal.severity.value.lower(), 50)
        confidence_val = signal.confidence or 50
        
        # Simple weighted average prioritizing severity
        risk = (severity_val * 0.7) + (confidence_val * 0.3)
        
        return min(max(int(risk), 0), 100)
