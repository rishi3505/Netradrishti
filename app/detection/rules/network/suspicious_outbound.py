from app.detection.rules.base import DetectionRule
from app.schemas.detection import DetectionRuleSchema, DetectionRuleConfig
from app.schemas.normalized_event import NormalizedEvent
from app.schemas.signal import SecuritySignal, DetectionMethod
from app.schemas.common import Severity
from app.detection.context import DetectionContext
from typing import Optional

class SuspiciousOutboundRule(DetectionRule):
    @classmethod
    def get_metadata(cls) -> DetectionRuleSchema:
        return DetectionRuleSchema(
            rule_id="NET-003",
            rule_name="Suspicious Outbound Connection",
            description="Detects an internal host connecting to an external IP on an unusual port.",
            version="1.0",
            enabled=True,
            severity=Severity.MEDIUM,
            category="Network",
            mitre_mapping=["T1043"],
            detection_type="rule_based",
            config=cls.get_default_config()
        )

    @classmethod
    def get_default_config(cls) -> DetectionRuleConfig:
        return DetectionRuleConfig(
            enabled=True,
            threshold=1,
            window_minutes=1,
            severity=Severity.MEDIUM,
            custom_params={
                "allowed_ports": [80, 443, 53, 123],
                "internal_networks": ["10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3"]
            }
        )

    def _is_internal(self, ip_str: str) -> bool:
        for net in self.config.custom_params.get("internal_networks", []):
            if ip_str.startswith(net):
                return True
        return False

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
        dest_port = event.event.network.destination_port
        
        # Check if source is internal and dest is external
        if self._is_internal(source_ip) and not self._is_internal(dest_ip):
            if dest_port not in self.config.custom_params.get("allowed_ports", []):
                evidence = self.collect_evidence(
                    source_ip=source_ip,
                    destination_ip=dest_ip,
                    destination_port=dest_port
                )
                
                return SecuritySignal(
                    signal_type="Suspicious Outbound Connection",
                    detection_method=DetectionMethod.RULE_BASED,
                    detection_rule_id="NET-003",
                    title=f"Suspicious Outbound Connection to Port {dest_port}",
                    description=f"Internal host {source_ip} connected to external IP {dest_ip} on unusual port {dest_port}.",
                    severity=self.config.severity,
                    related_event_ids=[event.event.identity.event_id],
                    affected_entities=[source_ip, dest_ip],
                    evidence=evidence
                )
        return None
