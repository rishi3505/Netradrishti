from app.detection.rules.base import DetectionRule
from app.schemas.detection import DetectionRuleSchema, DetectionRuleConfig
from app.schemas.normalized_event import NormalizedEvent
from app.schemas.signal import SecuritySignal, DetectionMethod
from app.schemas.common import Severity
from app.detection.context import DetectionContext
from typing import Optional

class BruteForceRule(DetectionRule):
    @classmethod
    def get_metadata(cls) -> DetectionRuleSchema:
        return DetectionRuleSchema(
            rule_id="AUTH-001",
            rule_name="Brute Force Authentication",
            description="Detects multiple authentication failures from the same source to the same account.",
            version="1.0",
            enabled=True,
            severity=Severity.HIGH,
            category="Authentication",
            mitre_mapping=["T1110"],
            detection_type="threshold_based",
            config=cls.get_default_config()
        )

    @classmethod
    def get_default_config(cls) -> DetectionRuleConfig:
        return DetectionRuleConfig(
            enabled=True,
            threshold=10,
            window_minutes=5,
            severity=Severity.HIGH
        )

    def is_applicable(self, event: NormalizedEvent) -> bool:
        cls = event.event.classification
        return (cls.event_category == "authentication" and 
                cls.outcome == "failure" and 
                event.event.network is not None and 
                event.event.network.source_ip is not None and
                event.event.user is not None and 
                event.event.user.username is not None)

    async def analyze(self, event: NormalizedEvent, context: DetectionContext) -> Optional[SecuritySignal]:
        source_ip = str(event.event.network.source_ip)
        username = event.event.user.username
        
        # Get historical failures for this IP and username
        recent_events = await context.get_events_for_source_ip(
            source_ip, 
            window_minutes=self.config.window_minutes,
            category="authentication"
        )
        
        failures = [
            e for e in recent_events 
            if e.classification.outcome == "failure" and 
               e.user and e.user.username == username
        ]
        
        if len(failures) >= self.config.threshold:
            evidence = self.collect_evidence(
                source_ip=source_ip,
                target_user=username,
                failures_count=len(failures),
                window_minutes=self.config.window_minutes
            )
            
            return SecuritySignal(
                signal_type="Brute Force Attack",
                detection_method=DetectionMethod.RULE_BASED,
                detection_rule_id="AUTH-001",
                title=f"Possible Brute Force Attack against {username} from {source_ip}",
                description=f"Detected {len(failures)} failed login attempts from {source_ip} against {username} within {self.config.window_minutes} minutes.",
                severity=self.config.severity,
                related_event_ids=[e.identity.event_id for e in failures],
                affected_entities=[source_ip, username],
                evidence=evidence
            )
        return None
