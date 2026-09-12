from app.correlation.rules.base import CorrelationRule
from app.schemas.correlation import CorrelationRuleSchema, CorrelationRuleConfig
from app.schemas.signal import SecuritySignal
from app.schemas.incident import Incident
from app.schemas.common import Severity
from app.correlation.context import CorrelationContext
from typing import Optional

class PortScanFollowupRule(CorrelationRule):
    @classmethod
    def get_metadata(cls) -> CorrelationRuleSchema:
        return CorrelationRuleSchema(
            rule_id="CORR-003",
            rule_name="Port Scan Follow-up Activity",
            description="Correlates a Port Scan signal with subsequent connections or authentications from the same source.",
            enabled=True,
            severity=Severity.MEDIUM,
            mitre_mapping=["T1046"],
            config=cls.get_default_config()
        )

    @classmethod
    def get_default_config(cls) -> CorrelationRuleConfig:
        return CorrelationRuleConfig(
            enabled=True,
            window_minutes=60,
            severity_override=None # Inherit from signals
        )

    def is_applicable(self, new_signal: SecuritySignal) -> bool:
        # We trigger if we see a port scan (NET-001) OR an auth signal (AUTH-001, AUTH-003)
        return new_signal.detection_rule_id in ["NET-001", "AUTH-001", "AUTH-003", "NET-002"]

    async def analyze(self, new_signal: SecuritySignal, context: CorrelationContext) -> Optional[Incident]:
        recent_signals = await context.get_recent_signals(self.config.window_minutes)
        
        has_scan = new_signal.detection_rule_id == "NET-001"
        scan_signal = new_signal if has_scan else None
        other_signals = []
        
        if not has_scan:
            other_signals.append(new_signal)
            
        for sig in recent_signals:
            if sig.signal_id == new_signal.signal_id:
                continue
            if sig.detection_rule_id == "NET-001":
                scan_signal = sig
            elif sig.detection_rule_id in ["AUTH-001", "AUTH-003", "NET-002"]:
                other_signals.append(sig)
                
        if scan_signal and other_signals:
            # Check for shared entities (e.g. source IP)
            shared_entities = set(scan_signal.affected_entities)
            for sig in other_signals:
                if shared_entities.intersection(set(sig.affected_entities)):
                    signals = [scan_signal] + [s for s in other_signals if shared_entities.intersection(set(s.affected_entities))]
                    all_entities = set()
                    for s in signals:
                        all_entities.update(s.affected_entities)
                        
                    reason = [
                        "Port scan detected",
                        "Follow-up authentication or network activity observed from the same source"
                    ]
                    
                    return self.create_incident(
                        title="Suspicious Activity Following Port Scan",
                        description="A source performed scanning against a host and shortly afterward generated another suspicious signal.",
                        signals=signals,
                        affected_entities=all_entities,
                        mitre=self.get_metadata().mitre_mapping,
                        reason=reason
                    )
        return None
