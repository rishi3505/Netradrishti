from typing import List, Optional, Any
from app.schemas.normalized_event import NormalizedEvent
from app.schemas.event import UnifiedSecurityEvent
from app.detection.window import EventWindow
from datetime import datetime

class DetectionContext:
    """
    Context provided to detection rules, containing the current event
    and mechanisms to query historical data.
    """
    def __init__(self, current_event: NormalizedEvent, window: EventWindow):
        self.current_event = current_event
        self.window = window
        self._cache = {}

    async def get_events_for_source_ip(self, ip: str, window_minutes: int, category: Optional[str] = None, event_type: Optional[str] = None) -> List[UnifiedSecurityEvent]:
        cache_key = f"source_ip_{ip}_{window_minutes}_{category}_{event_type}"
        if cache_key in self._cache:
            return self._cache[cache_key]
            
        events = await self.window.get_recent_events(window_minutes, category, event_type)
        filtered_events = [
            e for e in events 
            if e.network and e.network.source_ip and str(e.network.source_ip) == ip
        ]
        self._cache[cache_key] = filtered_events
        return filtered_events

    async def get_events_for_user(self, username: str, window_minutes: int, category: Optional[str] = None, event_type: Optional[str] = None) -> List[UnifiedSecurityEvent]:
        cache_key = f"user_{username}_{window_minutes}_{category}_{event_type}"
        if cache_key in self._cache:
            return self._cache[cache_key]
            
        events = await self.window.get_recent_events(window_minutes, category, event_type)
        filtered_events = [
            e for e in events 
            if e.user and e.user.username and e.user.username == username
        ]
        self._cache[cache_key] = filtered_events
        return filtered_events
        
    async def get_events_for_host(self, ip: str, window_minutes: int, category: Optional[str] = None, event_type: Optional[str] = None) -> List[UnifiedSecurityEvent]:
        cache_key = f"host_{ip}_{window_minutes}_{category}_{event_type}"
        if cache_key in self._cache:
            return self._cache[cache_key]
            
        events = await self.window.get_recent_events(window_minutes, category, event_type)
        filtered_events = [
            e for e in events 
            if (e.source_host and e.source_host.ip and str(e.source_host.ip) == ip) or 
               (e.destination_host and e.destination_host.ip and str(e.destination_host.ip) == ip)
        ]
        self._cache[cache_key] = filtered_events
        return filtered_events

    async def get_all_recent_events(self, window_minutes: int, category: Optional[str] = None, event_type: Optional[str] = None) -> List[UnifiedSecurityEvent]:
        cache_key = f"all_{window_minutes}_{category}_{event_type}"
        if cache_key in self._cache:
            return self._cache[cache_key]
            
        events = await self.window.get_recent_events(window_minutes, category, event_type)
        self._cache[cache_key] = events
        return events
