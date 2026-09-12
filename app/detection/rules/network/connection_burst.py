from app.detection.rules.base import DetectionRule
from app.schemas.detection import DetectionRuleSchema, DetectionRuleConfig
from app.schemas.normalized_event import NormalizedEvent
from app.schemas.signal import SecuritySignal, DetectionMethod
from app.schemas.common import Severity
from app.detection.context import DetectionContext
from typing import Optional

class ConnectionBurstRule(DetectionRule):
    @classmethod
    def get_metadata(cls) -> DetectionRuleSchema:
        return DetectionRuleSchema(
            rule_id="NET-002",
            rule_name="Network Connection Burst",
            description="Detects an unusual volume of connections from a single source.",
            version="1.0",
            enabled=True,
            severity=Severity.LOW,
            category="Network",
            mitre_mapping=[],
            detection_type="behavioral",
            config=cls.get_default_config()
        )

    @classmethod
    def get_default_config(cls) -> DetectionRuleConfig:
        return DetectionRuleConfig(
            enabled=True,
            threshold=500, # 500 connections in the window
            window_minutes=1,
            severity=Severity.LOW
        )

    def is_applicable(self, event: NormalizedEvent) -> bool:
        cls = event.event.classification
        return (cls.event_category == "network" and 
                event.event.network is not None and 
                event.event.network.source_ip is not None)

    async def analyze(self, event: NormalizedEvent, context: DetectionContext) -> Optional[SecuritySignal]:
        source_ip = str(event.event.network.source_ip)
        
        recent_events = await context.get_events_for_source_ip(
            source_ip, 
            window_minutes=self.config.window_minutes,
            category="network"
        )
        
        connection_count = len(recent_events)
        
        if connection_count >= self.config.threshold:
            evidence = self.collect_evidence(
                source_ip=source_ip,
                connection_count=connection_count,
                threshold=self.config.threshold,
                window_minutes=self.config.window_minutes
            )
            
            return SecuritySignal(
                signal_type="Connection Burst",
                detection_method=DetectionMethod.BEHAVIORAL,
                detection_rule_id="NET-002",
                title=f"Network Connection Burst from {source_ip}",
                description=f"Observed {connection_count} connections from {source_ip} in the last {self.config.window_minutes} minutes.",
                severity=self.config.severity,
                related_event_ids=[e.identity.event_id for e in recent_events[:50]], # Only attach first 50 as evidence
                affected_entities=[source_ip],
                evidence=evidence
            )
        return None
