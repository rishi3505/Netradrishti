from app.correlation.rules.base import CorrelationRule
from app.schemas.correlation import CorrelationRuleSchema, CorrelationRuleConfig
from app.schemas.signal import SecuritySignal
from app.schemas.incident import Incident
from app.schemas.common import Severity
from app.correlation.context import CorrelationContext
from typing import Optional

class PasswordSprayingIncidentRule(CorrelationRule):
    @classmethod
    def get_metadata(cls) -> CorrelationRuleSchema:
        return CorrelationRuleSchema(
            rule_id="CORR-002",
            rule_name="Password Spraying Campaign",
            description="Elevates Password Spraying signals into an incident if multiple occur or affect many users.",
            enabled=True,
            severity=Severity.HIGH,
            mitre_mapping=["T1110.003"],
            config=cls.get_default_config()
        )

    @classmethod
    def get_default_config(cls) -> CorrelationRuleConfig:
        return CorrelationRuleConfig(
            enabled=True,
            window_minutes=60,
            severity_override=Severity.HIGH
        )

    def is_applicable(self, new_signal: SecuritySignal) -> bool:
        return new_signal.detection_rule_id == "AUTH-002"

    async def analyze(self, new_signal: SecuritySignal, context: CorrelationContext) -> Optional[Incident]:
        # For this rule, we can create an incident directly from a high-confidence password spraying signal
        # or if there are multiple signals from the same IP.
        
        recent_signals = await context.get_recent_signals_by_rule("AUTH-002", self.config.window_minutes)
        
        # Filter signals sharing the source IP
        source_ip = None
        for entity in new_signal.affected_entities:
            # Simple heuristic, assume first entity might be IP, or check all
            # But the signal itself should have the source_ip in affected_entities
            source_ip = entity
            break
            
        related_signals = [
            sig for sig in recent_signals 
            if source_ip in sig.affected_entities
        ]
        
        if not related_signals:
            related_signals = [new_signal]
            
        # Ensure new_signal is in the list
        if new_signal.signal_id not in [s.signal_id for s in related_signals]:
            related_signals.append(new_signal)
            
        all_entities = set()
        for sig in related_signals:
            all_entities.update(sig.affected_entities)
            
        reason = [
            "Password spraying behavior detected",
            f"Source IP targeted {len(all_entities)-1} accounts"
        ]
        
        return self.create_incident(
            title="Password Spraying Campaign",
            description="One source IP attempted authentication against multiple accounts within a short time window.",
            signals=related_signals,
            affected_entities=all_entities,
            mitre=self.get_metadata().mitre_mapping,
            reason=reason
        )
