from app.detection.rules.base import DetectionRule
from app.schemas.detection import DetectionRuleSchema, DetectionRuleConfig
from app.schemas.normalized_event import NormalizedEvent
from app.schemas.signal import SecuritySignal, DetectionMethod
from app.schemas.common import Severity
from app.detection.context import DetectionContext
from typing import Optional

class PasswordSprayingRule(DetectionRule):
    @classmethod
    def get_metadata(cls) -> DetectionRuleSchema:
        return DetectionRuleSchema(
            rule_id="AUTH-002",
            rule_name="Password Spraying",
            description="Detects an IP attempting to authenticate against multiple different users with failures.",
            version="1.0",
            enabled=True,
            severity=Severity.HIGH,
            category="Authentication",
            mitre_mapping=["T1110.003"],
            detection_type="threshold_based",
            config=cls.get_default_config()
        )

    @classmethod
    def get_default_config(cls) -> DetectionRuleConfig:
        return DetectionRuleConfig(
            enabled=True,
            threshold=5, # 5 different users
            window_minutes=15,
            severity=Severity.HIGH
        )

    def is_applicable(self, event: NormalizedEvent) -> bool:
        cls = event.event.classification
        return (cls.event_category == "authentication" and 
                cls.outcome == "failure" and 
                event.event.network is not None and 
                event.event.network.source_ip is not None)

    async def analyze(self, event: NormalizedEvent, context: DetectionContext) -> Optional[SecuritySignal]:
        source_ip = str(event.event.network.source_ip)
        
        recent_events = await context.get_events_for_source_ip(
            source_ip, 
            window_minutes=self.config.window_minutes,
            category="authentication"
        )
        
        failures = [e for e in recent_events if e.classification.outcome == "failure" and e.user and e.user.username]
        targeted_users = set(e.user.username for e in failures)
        
        if len(targeted_users) >= self.config.threshold:
            evidence = self.collect_evidence(
                source_ip=source_ip,
                targeted_users_count=len(targeted_users),
                total_failures=len(failures),
                targeted_users=list(targeted_users),
                window_minutes=self.config.window_minutes
            )
            
            return SecuritySignal(
                signal_type="Password Spraying",
                detection_method=DetectionMethod.RULE_BASED,
                detection_rule_id="AUTH-002",
                title=f"Possible Password Spraying from {source_ip}",
                description=f"Detected failed logins to {len(targeted_users)} different accounts from {source_ip} within {self.config.window_minutes} minutes.",
                severity=self.config.severity,
                related_event_ids=[e.identity.event_id for e in failures],
                affected_entities=[source_ip] + list(targeted_users),
                evidence=evidence
            )
        return None
