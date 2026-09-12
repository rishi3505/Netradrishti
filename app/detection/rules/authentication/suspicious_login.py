from app.detection.rules.base import DetectionRule
from app.schemas.detection import DetectionRuleSchema, DetectionRuleConfig
from app.schemas.normalized_event import NormalizedEvent
from app.schemas.signal import SecuritySignal, DetectionMethod
from app.schemas.common import Severity
from app.detection.context import DetectionContext
from typing import Optional

class SuspiciousLoginRule(DetectionRule):
    @classmethod
    def get_metadata(cls) -> DetectionRuleSchema:
        return DetectionRuleSchema(
            rule_id="AUTH-003",
            rule_name="Suspicious Successful Login",
            description="Detects a successful login immediately following multiple failures.",
            version="1.0",
            enabled=True,
            severity=Severity.CRITICAL,
            category="Authentication",
            mitre_mapping=["T1078"],
            detection_type="sequence_based",
            config=cls.get_default_config()
        )

    @classmethod
    def get_default_config(cls) -> DetectionRuleConfig:
        return DetectionRuleConfig(
            enabled=True,
            threshold=5, # 5 prior failures
            window_minutes=10,
            severity=Severity.CRITICAL
        )

    def is_applicable(self, event: NormalizedEvent) -> bool:
        cls = event.event.classification
        return (cls.event_category == "authentication" and 
                cls.outcome == "success" and 
                event.event.network is not None and 
                event.event.network.source_ip is not None and
                event.event.user is not None and 
                event.event.user.username is not None)

    async def analyze(self, event: NormalizedEvent, context: DetectionContext) -> Optional[SecuritySignal]:
        source_ip = str(event.event.network.source_ip)
        username = event.event.user.username
        
        recent_events = await context.get_events_for_source_ip(
            source_ip, 
            window_minutes=self.config.window_minutes,
            category="authentication"
        )
        
        # Look for prior failures for the same user
        prior_failures = [
            e for e in recent_events 
            if e.classification.outcome == "failure" and 
               e.user and e.user.username == username and
               e.identity.timestamp < event.event.identity.timestamp
        ]
        
        if len(prior_failures) >= self.config.threshold:
            evidence = self.collect_evidence(
                source_ip=source_ip,
                target_user=username,
                prior_failures_count=len(prior_failures),
                window_minutes=self.config.window_minutes,
                success_event_id=str(event.event.identity.event_id)
            )
            
            return SecuritySignal(
                signal_type="Suspicious Login",
                detection_method=DetectionMethod.SEQUENCE_DETECTION,
                detection_rule_id="AUTH-003",
                title=f"Suspicious Successful Login for {username} from {source_ip}",
                description=f"Successful login for {username} observed after {len(prior_failures)} failures from {source_ip} within {self.config.window_minutes} minutes.",
                severity=self.config.severity,
                related_event_ids=[e.identity.event_id for e in prior_failures] + [event.event.identity.event_id],
                affected_entities=[source_ip, username],
                evidence=evidence
            )
        return None
