from app.correlation.rules.base import CorrelationRule
from app.schemas.correlation import CorrelationRuleSchema, CorrelationRuleConfig
from app.schemas.signal import SecuritySignal
from app.schemas.incident import Incident
from app.schemas.common import Severity
from app.correlation.context import CorrelationContext
from typing import Optional

class MultiSourceRule(CorrelationRule):
    @classmethod
    def get_metadata(cls) -> CorrelationRuleSchema:
        return CorrelationRuleSchema(
            rule_id="CORR-006",
            rule_name="Multi-Source Correlation",
            description="Correlates signals from multiple independent sources targeting the same entity.",
            enabled=True,
            severity=Severity.HIGH,
            mitre_mapping=[],
            config=cls.get_default_config()
        )

    @classmethod
    def get_default_config(cls) -> CorrelationRuleConfig:
        return CorrelationRuleConfig(
            enabled=True,
            window_minutes=60,
            severity_override=None
        )

    def is_applicable(self, new_signal: SecuritySignal) -> bool:
        return True # Evaluate all signals

    async def analyze(self, new_signal: SecuritySignal, context: CorrelationContext) -> Optional[Incident]:
        recent_signals = await context.get_recent_signals(self.config.window_minutes)
        
        for entity in new_signal.affected_entities:
            entity_signals = [sig for sig in recent_signals if entity in sig.affected_entities]
            
            if new_signal.signal_id not in [s.signal_id for s in entity_signals]:
                entity_signals.append(new_signal)
                
            # If we have multiple signals from the same entity, check their rule types or sources
            unique_rules = set(sig.detection_rule_id for sig in entity_signals if sig.detection_rule_id)
            
            # We want at least 2 different rules firing on the same entity
            if len(unique_rules) >= 2:
                reason = [
                    f"Multiple independent detection rules triggered for entity: {entity}",
                    f"Rules involved: {list(unique_rules)}"
                ]
                
                all_entities = set()
                for s in entity_signals:
                    all_entities.update(s.affected_entities)
                    
                return self.create_incident(
                    title="Multi-Source Suspicious Activity",
                    description=f"Multiple distinct suspicious activities were detected for {entity}.",
                    signals=entity_signals,
                    affected_entities=all_entities,
                    mitre=self.get_metadata().mitre_mapping,
                    reason=reason
                )
        return None
