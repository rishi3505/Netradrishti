from app.correlation.rules.base import CorrelationRule
from app.schemas.correlation import CorrelationRuleSchema, CorrelationRuleConfig
from app.schemas.signal import SecuritySignal
from app.schemas.incident import Incident
from app.schemas.common import Severity
from app.correlation.context import CorrelationContext
from typing import Optional

class BruteForceSuccessRule(CorrelationRule):
    @classmethod
    def get_metadata(cls) -> CorrelationRuleSchema:
        return CorrelationRuleSchema(
            rule_id="CORR-001",
            rule_name="Brute Force Leading to Success",
            description="Correlates Brute Force signals with subsequent Suspicious Successful Login signals.",
            enabled=True,
            severity=Severity.HIGH,
            mitre_mapping=["T1110", "T1078"],
            config=cls.get_default_config()
        )

    @classmethod
    def get_default_config(cls) -> CorrelationRuleConfig:
        return CorrelationRuleConfig(
            enabled=True,
            window_minutes=30,
            severity_override=Severity.HIGH
        )

    def is_applicable(self, new_signal: SecuritySignal) -> bool:
        return new_signal.detection_rule_id in ["AUTH-001", "AUTH-003"]

    async def analyze(self, new_signal: SecuritySignal, context: CorrelationContext) -> Optional[Incident]:
        recent_signals = await context.get_recent_signals(self.config.window_minutes)
        
        # We need both AUTH-001 (Brute Force) and AUTH-003 (Suspicious Login)
        target_rule_to_find = "AUTH-003" if new_signal.detection_rule_id == "AUTH-001" else "AUTH-001"
        
        for sig in recent_signals:
            if sig.detection_rule_id == target_rule_to_find:
                # Check entity intersection
                if set(sig.affected_entities).intersection(set(new_signal.affected_entities)):
                    signals = [new_signal, sig]
                    entities = set(new_signal.affected_entities).union(set(sig.affected_entities))
                    reason = [
                        "Authentication failure sequence followed by success",
                        f"Shared entities: {list(entities)}"
                    ]
                    
                    return self.create_incident(
                        title="Potential Credential Compromise via Brute Force",
                        description="Multiple authentication failures followed by a successful login detected.",
                        signals=signals,
                        affected_entities=entities,
                        mitre=self.get_metadata().mitre_mapping,
                        reason=reason
                    )
        return None
