from typing import Dict, Any
from datetime import datetime
from uuid import uuid4
from app.connectors.base import BaseConnector
from app.connectors.exceptions import ValidationError, TransformationError
from app.schemas.event import UnifiedSecurityEvent, EventSource, EventClassification, RawEvent
from app.schemas.common import HostInfo, UserInfo, NetworkInfo

class WindowsConnector(BaseConnector):
    
    def validate_raw_event(self, raw_event: Dict[str, Any]) -> bool:
        if "EventID" not in raw_event:
            raise ValidationError("Missing 'EventID' in Windows raw event.")
        if "TimeCreated" not in raw_event:
            raise ValidationError("Missing 'TimeCreated' in Windows raw event.")
        return True

    def transform(self, raw_event: Dict[str, Any]) -> UnifiedSecurityEvent:
        self.validate_raw_event(raw_event)
        
        event_id_str = str(raw_event.get("EventID"))
        time_created_str = raw_event.get("TimeCreated")
        
        try:
            timestamp = datetime.fromisoformat(time_created_str.replace("Z", "+00:00"))
        except ValueError:
            timestamp = datetime.utcnow()
            
        # Determine classification
        category = "system"
        event_type = "unknown"
        action = None
        outcome = None
        
        if event_id_str == "4624":
            category = "authentication"
            event_type = "authentication_success"
            action = "logon"
            outcome = "success"
        elif event_id_str == "4625":
            category = "authentication"
            event_type = "authentication_failure"
            action = "logon"
            outcome = "failure"
        elif event_id_str == "4634":
            category = "authentication"
            event_type = "logout"
            action = "logoff"
            outcome = "success"
            
        source = EventSource(
            source_name=raw_event.get("Computer", "Unknown"),
            source_type="windows",
            vendor="Microsoft",
            product="Windows"
        )
        
        classification = EventClassification(
            event_category=category,
            event_type=event_type,
            event_action=action,
            outcome=outcome
        )
        
        user = UserInfo(
            username=raw_event.get("TargetUserName"),
            domain=raw_event.get("TargetDomainName")
        )
        
        host = HostInfo(
            hostname=raw_event.get("Computer"),
            ip=raw_event.get("IpAddress")
        )
        
        raw = RawEvent(
            raw_event=raw_event,
            raw_event_format="json",
            source_event_id=event_id_str,
            source_timestamp=timestamp
        )
        
        return UnifiedSecurityEvent(
            source=source,
            classification=classification,
            user=user,
            source_host=host,
            raw=raw
        )

    def get_source_metadata(self) -> Dict[str, Any]:
        return {
            "source_type": "windows",
            "description": "Windows Security Event Logs Connector",
            "version": "1.0.0"
        }

    def health_check(self) -> bool:
        return True
