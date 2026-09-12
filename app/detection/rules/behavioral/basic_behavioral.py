from app.detection.rules.base import DetectionRule
from app.schemas.detection import DetectionRuleSchema, DetectionRuleConfig
from app.schemas.normalized_event import NormalizedEvent
from app.schemas.signal import SecuritySignal, DetectionMethod
from app.schemas.common import Severity
from app.detection.context import DetectionContext
from typing import Optional

class BasicBehavioralRule(DetectionRule):
    @classmethod
    def get_metadata(cls) -> DetectionRuleSchema:
        return DetectionRuleSchema(
            rule_id="BEH-001",
            rule_name="Basic Behavioral Deviation",
            description="Monitors login frequency and flags large deviations.",
            version="1.0",
            enabled=True,
            severity=Severity.LOW,
            category="Behavioral",
            mitre_mapping=[],
            detection_type="behavioral",
            config=cls.get_default_config()
        )

    @classmethod
    def get_default_config(cls) -> DetectionRuleConfig:
        return DetectionRuleConfig(
            enabled=True,
            threshold=100, # 100 logins in an hour is suspicious
            window_minutes=60,
            severity=Severity.LOW
        )

    def is_applicable(self, event: NormalizedEvent) -> bool:
        cls = event.event.classification
        return (cls.event_category == "authentication" and 
                cls.outcome == "success" and 
                event.event.user is not None and 
                event.event.user.username is not None)

    async def analyze(self, event: NormalizedEvent, context: DetectionContext) -> Optional[SecuritySignal]:
        username = event.event.user.username
        
        recent_events = await context.get_events_for_user(
            username, 
            window_minutes=self.config.window_minutes,
            category="authentication"
        )
        
        successes = [e for e in recent_events if e.classification.outcome == "success"]
        login_count = len(successes)
        
        if login_count >= self.config.threshold:
            evidence = self.collect_evidence(
                username=username,
                login_count=login_count,
                threshold=self.config.threshold,
                window_minutes=self.config.window_minutes
            )
            
            return SecuritySignal(
                signal_type="High Login Frequency",
                detection_method=DetectionMethod.BEHAVIORAL,
                detection_rule_id="BEH-001",
                title=f"Unusually High Login Frequency for {username}",
                description=f"Observed {login_count} successful logins for {username} in the last {self.config.window_minutes} minutes.",
                severity=self.config.severity,
                related_event_ids=[e.identity.event_id for e in successes[:50]],
                affected_entities=[username],
                evidence=evidence
            )
        return None
