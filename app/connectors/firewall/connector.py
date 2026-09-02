from typing import Dict, Any
from datetime import datetime
from app.connectors.base import BaseConnector
from app.connectors.exceptions import ValidationError
from app.schemas.event import UnifiedSecurityEvent, EventSource, EventClassification, RawEvent
from app.schemas.common import NetworkInfo

class FirewallConnector(BaseConnector):
    
    def validate_raw_event(self, raw_event: Dict[str, Any]) -> bool:
        required_fields = ["timestamp", "action"]
        for field in required_fields:
            if field not in raw_event:
                raise ValidationError(f"Missing '{field}' in Firewall raw event.")
        return True

    def transform(self, raw_event: Dict[str, Any]) -> UnifiedSecurityEvent:
        self.validate_raw_event(raw_event)
        
        timestamp_str = raw_event.get("timestamp")
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except ValueError:
            timestamp = datetime.utcnow()
            
        action = str(raw_event.get("action")).lower()
        outcome = "success" if action in ["allowed", "accept"] else "failure"
        
        source = EventSource(
            source_name="Generic Firewall",
            source_type="firewall",
            vendor="Generic",
            product="Firewall"
        )
        
        classification = EventClassification(
            event_category="network",
            event_type="network_traffic",
            event_action=action,
            outcome=outcome
        )
        
        network = NetworkInfo(
            source_ip=raw_event.get("src_ip"),
            source_port=raw_event.get("src_port"),
            destination_ip=raw_event.get("dst_ip"),
            destination_port=raw_event.get("dst_port"),
            protocol=raw_event.get("protocol"),
            bytes_sent=raw_event.get("bytes"),
            packets_sent=raw_event.get("packets")
        )
        
        raw = RawEvent(
            raw_event=raw_event,
            raw_event_format="json",
            source_timestamp=timestamp
        )
        
        return UnifiedSecurityEvent(
            source=source,
            classification=classification,
            network=network,
            raw=raw
        )

    def get_source_metadata(self) -> Dict[str, Any]:
        return {
            "source_type": "firewall",
            "description": "Generic Firewall Network Event Connector",
            "version": "1.0.0"
        }

    def health_check(self) -> bool:
        return True
