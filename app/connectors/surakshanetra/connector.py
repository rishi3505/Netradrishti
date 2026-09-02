from typing import Dict, Any
from datetime import datetime
from app.connectors.base import BaseConnector
from app.connectors.exceptions import ValidationError
from app.schemas.event import UnifiedSecurityEvent, EventSource, EventClassification, RawEvent
from app.schemas.common import NetworkInfo, HostInfo, SecurityContext, Severity

class SurakshaNetraConnector(BaseConnector):
    
    def validate_raw_event(self, raw_event: Dict[str, Any]) -> bool:
        required_fields = ["event_id", "timestamp", "signal_type"]
        for field in required_fields:
            if field not in raw_event:
                raise ValidationError(f"Missing '{field}' in SurakshaNetra raw event.")
        return True

    def transform(self, raw_event: Dict[str, Any]) -> UnifiedSecurityEvent:
        self.validate_raw_event(raw_event)
        
        timestamp_str = raw_event.get("timestamp")
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except ValueError:
            timestamp = datetime.utcnow()
            
        source = EventSource(
            source_name="SurakshaNetra",
            source_type="surakshanetra",
            vendor="Netradhrishti",
            product="SurakshaNetra"
        )
        
        classification = EventClassification(
            event_category="security_signal",
            event_type=raw_event.get("signal_type", "unknown_signal"),
            outcome="alert"
        )
        
        network = NetworkInfo(
            source_ip=raw_event.get("source_ip"),
            destination_ip=raw_event.get("destination_ip")
        )
        
        source_host = HostInfo(hostname=raw_event.get("source_host")) if raw_event.get("source_host") else None
        dest_host = HostInfo(hostname=raw_event.get("destination_host")) if raw_event.get("destination_host") else None
        
        # Severity mapping
        raw_sev = str(raw_event.get("severity", "info")).lower()
        try:
            severity = Severity(raw_sev)
        except ValueError:
            severity = Severity.INFO
            
        security_context = SecurityContext(
            severity=severity,
            confidence=raw_event.get("confidence"),
            labels={
                "title": raw_event.get("title", ""),
                "detection_method": raw_event.get("detection_method", "unknown")
            }
        )
        
        raw = RawEvent(
            raw_event=raw_event,
            raw_event_format="json",
            source_event_id=str(raw_event.get("event_id")),
            source_timestamp=timestamp
        )
        
        event = UnifiedSecurityEvent(
            source=source,
            classification=classification,
            network=network,
            source_host=source_host,
            destination_host=dest_host,
            security_context=security_context,
            raw=raw
        )
        
        # Preserve specific custom fields from SurakshaNetra
        event.custom_fields["affected_entities"] = raw_event.get("affected_entities", [])
        event.custom_fields["evidence"] = raw_event.get("evidence", {})
        event.custom_fields["metadata"] = raw_event.get("metadata", {})
        event.custom_fields["description"] = raw_event.get("description", "")
        
        return event

    def get_source_metadata(self) -> Dict[str, Any]:
        return {
            "source_type": "surakshanetra",
            "description": "SurakshaNetra Security Signal Connector",
            "version": "1.0.0"
        }

    def health_check(self) -> bool:
        return True
