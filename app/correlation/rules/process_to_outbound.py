from app.correlation.rules.base import CorrelationRule
from app.schemas.correlation import CorrelationRuleSchema, CorrelationRuleConfig
from app.schemas.signal import SecuritySignal
from app.schemas.incident import Incident
from app.schemas.common import Severity
from app.correlation.context import CorrelationContext
from typing import Optional

class ProcessToOutboundRule(CorrelationRule):
    @classmethod
    def get_metadata(cls) -> CorrelationRuleSchema:
        return CorrelationRuleSchema(
            rule_id="CORR-005",
            rule_name="Process Execution to Outbound Connection",
            description="Correlates Suspicious Process Execution signals with Suspicious Outbound Connection signals on the same host.",
            enabled=True,
            severity=Severity.HIGH,
            mitre_mapping=["T1059", "T1043"],
            config=cls.get_default_config()
        )

    @classmethod
    def get_default_config(cls) -> CorrelationRuleConfig:
        return CorrelationRuleConfig(
            enabled=True,
            window_minutes=15,
            severity_override=Severity.HIGH
        )

    def is_applicable(self, new_signal: SecuritySignal) -> bool:
        return new_signal.detection_rule_id in ["END-001", "NET-003"]

    async def analyze(self, new_signal: SecuritySignal, context: CorrelationContext) -> Optional[Incident]:
        recent_signals = await context.get_recent_signals(self.config.window_minutes)
        
        target_rule = "NET-003" if new_signal.detection_rule_id == "END-001" else "END-001"
        
        for sig in recent_signals:
            if sig.detection_rule_id == target_rule:
                if set(sig.affected_entities).intersection(set(new_signal.affected_entities)):
                    signals = [new_signal, sig]
                    entities = set(new_signal.affected_entities).union(set(sig.affected_entities))
                    
                    reason = [
                        "Suspicious process execution observed",
                        "Followed by a suspicious outbound network connection"
                    ]
                    
                    return self.create_incident(
                        title="Suspicious Activity Chain: Process to Network",
                        description="Suspicious process execution followed by an outbound network connection.",
                        signals=signals,
                        affected_entities=entities,
                        mitre=self.get_metadata().mitre_mapping,
                        reason=reason
                    )
        return None
