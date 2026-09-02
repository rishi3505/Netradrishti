from typing import Dict, Any
from datetime import datetime
from app.connectors.base import BaseConnector
from app.connectors.exceptions import ValidationError
from app.schemas.event import UnifiedSecurityEvent, EventSource, EventClassification, RawEvent
from app.schemas.common import NetworkInfo, SecurityContext, Severity

class SuricataConnector(BaseConnector):
    
    def validate_raw_event(self, raw_event: Dict[str, Any]) -> bool:
        if "timestamp" not in raw_event:
            raise ValidationError("Missing 'timestamp' in Suricata raw event.")
        if "event_type" not in raw_event:
            raise ValidationError("Missing 'event_type' in Suricata raw event.")
        return True

    def transform(self, raw_event: Dict[str, Any]) -> UnifiedSecurityEvent:
        self.validate_raw_event(raw_event)
        
        timestamp_str = raw_event.get("timestamp")
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except ValueError:
            timestamp = datetime.utcnow()
            
        event_type = raw_event.get("event_type")
        
        source = EventSource(
            source_name="Suricata IDS",
            source_type="suricata",
            vendor="OISF",
            product="Suricata"
        )
        
        classification = EventClassification(
            event_category="ids",
            event_type=f"suricata_{event_type}",
            outcome="alert" if event_type == "alert" else "success"
        )
        
        network = NetworkInfo(
            source_ip=raw_event.get("src_ip"),
            source_port=raw_event.get("src_port"),
            destination_ip=raw_event.get("dest_ip"),
            destination_port=raw_event.get("dest_port"),
            protocol=raw_event.get("proto")
        )
        
        security_context = None
        if event_type == "alert" and "alert" in raw_event:
            alert_data = raw_event["alert"]
            severity_mapping = {
                1: Severity.HIGH,
                2: Severity.MEDIUM,
                3: Severity.LOW,
                4: Severity.INFO
            }
            raw_severity = alert_data.get("severity", 4)
            severity = severity_mapping.get(raw_severity, Severity.INFO)
            
            security_context = SecurityContext(
                severity=severity,
                tags=[alert_data.get("category")] if alert_data.get("category") else [],
                labels={"signature": alert_data.get("signature", "unknown")}
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
            security_context=security_context,
            raw=raw
        )

    def get_source_metadata(self) -> Dict[str, Any]:
        return {
            "source_type": "suricata",
            "description": "Suricata IDS Alert Connector",
            "version": "1.0.0"
        }

    def health_check(self) -> bool:
        return True
