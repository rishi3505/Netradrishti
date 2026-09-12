from app.detection.rules.base import DetectionRule
from app.schemas.detection import DetectionRuleSchema, DetectionRuleConfig
from app.schemas.normalized_event import NormalizedEvent
from app.schemas.signal import SecuritySignal, DetectionMethod
from app.schemas.common import Severity
from app.detection.context import DetectionContext
from typing import Optional

class PortScanRule(DetectionRule):
    @classmethod
    def get_metadata(cls) -> DetectionRuleSchema:
        return DetectionRuleSchema(
            rule_id="NET-001",
            rule_name="Port Scanning",
            description="Detects a single source IP connecting to many different destination ports on a single host.",
            version="1.0",
            enabled=True,
            severity=Severity.MEDIUM,
            category="Network",
            mitre_mapping=["T1046"],
            detection_type="threshold_based",
            config=cls.get_default_config()
        )

    @classmethod
    def get_default_config(cls) -> DetectionRuleConfig:
        return DetectionRuleConfig(
            enabled=True,
            threshold=15, # 15 different ports
            window_minutes=5,
            severity=Severity.MEDIUM
        )

    def is_applicable(self, event: NormalizedEvent) -> bool:
        cls = event.event.classification
        return (cls.event_category == "network" and 
                event.event.network is not None and 
                event.event.network.source_ip is not None and
                event.event.network.destination_ip is not None and
                event.event.network.destination_port is not None)

    async def analyze(self, event: NormalizedEvent, context: DetectionContext) -> Optional[SecuritySignal]:
        source_ip = str(event.event.network.source_ip)
        dest_ip = str(event.event.network.destination_ip)
        
        recent_events = await context.get_events_for_source_ip(
            source_ip, 
            window_minutes=self.config.window_minutes,
            category="network"
        )
        
        # Filter for connections to the same destination host
        host_events = [
            e for e in recent_events 
            if e.network and e.network.destination_ip and str(e.network.destination_ip) == dest_ip
            and e.network.destination_port is not None
        ]
        
        targeted_ports = set(e.network.destination_port for e in host_events)
        
        if len(targeted_ports) >= self.config.threshold:
            evidence = self.collect_evidence(
                source_ip=source_ip,
                destination_ip=dest_ip,
                targeted_ports_count=len(targeted_ports),
                targeted_ports=list(targeted_ports),
                window_minutes=self.config.window_minutes
            )
            
            return SecuritySignal(
                signal_type="Port Scan",
                detection_method=DetectionMethod.RULE_BASED,
                detection_rule_id="NET-001",
                title=f"Possible Port Scan from {source_ip} to {dest_ip}",
                description=f"Detected connections to {len(targeted_ports)} different ports on {dest_ip} from {source_ip} within {self.config.window_minutes} minutes.",
                severity=self.config.severity,
                related_event_ids=[e.identity.event_id for e in host_events],
                affected_entities=[source_ip, dest_ip],
                evidence=evidence
            )
        return None
