from app.correlation.rules.base import CorrelationRule
from app.schemas.correlation import CorrelationRuleSchema, CorrelationRuleConfig
from app.schemas.signal import SecuritySignal
from app.schemas.incident import Incident
from app.schemas.common import Severity
from app.correlation.context import CorrelationContext
from typing import Optional

class LoginToProcessRule(CorrelationRule):
    @classmethod
    def get_metadata(cls) -> CorrelationRuleSchema:
        return CorrelationRuleSchema(
            rule_id="CORR-004",
            rule_name="Suspicious Login to Process Execution",
            description="Correlates Suspicious Login signals with Suspicious Process Execution signals on the same host.",
            enabled=True,
            severity=Severity.CRITICAL,
            mitre_mapping=["T1078", "T1059"],
            config=cls.get_default_config()
        )

    @classmethod
    def get_default_config(cls) -> CorrelationRuleConfig:
        return CorrelationRuleConfig(
            enabled=True,
            window_minutes=30,
            severity_override=Severity.CRITICAL
        )

    def is_applicable(self, new_signal: SecuritySignal) -> bool:
        return new_signal.detection_rule_id in ["AUTH-003", "END-001"]

    async def analyze(self, new_signal: SecuritySignal, context: CorrelationContext) -> Optional[Incident]:
        recent_signals = await context.get_recent_signals(self.config.window_minutes)
        
        target_rule = "END-001" if new_signal.detection_rule_id == "AUTH-003" else "AUTH-003"
        
        for sig in recent_signals:
            if sig.detection_rule_id == target_rule:
                if set(sig.affected_entities).intersection(set(new_signal.affected_entities)):
                    signals = [new_signal, sig]
                    entities = set(new_signal.affected_entities).union(set(sig.affected_entities))
                    
                    reason = [
                        "Suspicious successful login observed",
                        "Followed by suspicious process execution on the same host/account"
                    ]
                    
                    return self.create_incident(
                        title="Post-Compromise Process Execution",
                        description="A suspicious successful login was followed by suspicious process execution.",
                        signals=signals,
                        affected_entities=entities,
                        mitre=self.get_metadata().mitre_mapping,
                        reason=reason
                    )
        return None
