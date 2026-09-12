from typing import List, Optional
from app.schemas.signal import SecuritySignal
from app.schemas.incident import Incident
from app.correlation.rules.registry import CorrelationRuleRegistry
from app.correlation.context import CorrelationContext
from app.core.logging import get_logger
from sqlalchemy.ext.asyncio import AsyncSession

logger = get_logger(__name__)

class CorrelationEngine:
    def __init__(self):
        self.registry = CorrelationRuleRegistry

    async def analyze(self, new_signal: SecuritySignal, context: CorrelationContext) -> List[Incident]:
        """
        Runs the new signal against all correlation rules to see if it forms an incident
        with historical signals.
        """
        incidents = []
        rules = self.registry.get_all_rules()
        
        for rule in rules:
            if not rule.config.enabled:
                continue
                
            try:
                if rule.is_applicable(new_signal):
                    incident = await rule.analyze(new_signal, context)
                    if incident:
                        incidents.append(incident)
            except Exception as e:
                logger.error("Error executing correlation rule", rule_id=rule.get_metadata().rule_id, error=str(e))
                
        return incidents
