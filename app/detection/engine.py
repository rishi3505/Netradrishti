from typing import List
from app.schemas.normalized_event import NormalizedEvent
from app.schemas.signal import SecuritySignal
from app.detection.rules.registry import DetectionRuleRegistry
from app.detection.context import DetectionContext
from app.detection.scoring.confidence import ConfidenceCalculator
from app.detection.scoring.risk import RiskCalculator
from app.core.logging import get_logger

logger = get_logger(__name__)

class DetectionEngine:
    def __init__(self):
        self.registry = DetectionRuleRegistry

    async def analyze_event(self, event: NormalizedEvent, context: DetectionContext) -> List[SecuritySignal]:
        """
        Runs the normalized event through all applicable and enabled rules.
        """
        signals = []
        rules = self.registry.get_all_rules()
        
        for rule in rules:
            if not rule.config.enabled:
                continue
                
            try:
                if rule.is_applicable(event):
                    signal = await rule.analyze(event, context)
                    if signal:
                        # Calculate scores
                        signal.confidence = ConfidenceCalculator.calculate(signal, rule)
                        signal.risk_score = RiskCalculator.calculate(signal)
                        signals.append(signal)
            except Exception as e:
                logger.error("Error executing rule", rule_id=rule.get_metadata().rule_id, error=str(e))
                
        return signals
