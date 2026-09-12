from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timedelta
from app.models.database_models import DBIncident
from app.schemas.incident import Incident, IncidentStatus
from typing import Optional

class IncidentDeduplicator:
    """
    Deduplicates and merges incidents based on overlapping rules/entities.
    """
    def __init__(self, db: AsyncSession):
        self.db = db

    async def find_existing_incident(self, incident: Incident, window_minutes: int = 120) -> Optional[DBIncident]:
        """
        Finds an OPEN or NEW incident that shares the same correlation rules and affected entities.
        """
        now = datetime.utcnow()
        start_time = now - timedelta(minutes=window_minutes)
        
        query = select(DBIncident).where(
            DBIncident.status.in_([IncidentStatus.NEW.value, IncidentStatus.INVESTIGATING.value])
        ).where(
            DBIncident.created_at >= start_time
        )
        
        result = await self.db.execute(query)
        recent_incidents = result.scalars().all()
        
        new_entities = set(incident.affected_entities)
        
        for db_inc in recent_incidents:
            inc_data = db_inc.incident_data
            db_entities = set(inc_data.get('affected_entities', []))
            
            # Simple heuristic: If they share at least one entity and the title is the same (representing same rule outcome)
            if len(db_entities.intersection(new_entities)) > 0 and db_inc.title == incident.title:
                return db_inc
                
        return None
        
    async def merge_incidents(self, existing_db_inc: DBIncident, new_inc: Incident) -> DBIncident:
        """
        Merges new incident data into the existing one.
        """
        existing_data = existing_db_inc.incident_data
        
        # Merge signals
        existing_signals = set(existing_data.get('related_signal_ids', []))
        existing_signals.update([str(s) for s in new_inc.related_signal_ids])
        existing_data['related_signal_ids'] = list(existing_signals)
        
        # Merge events
        existing_events = set(existing_data.get('related_event_ids', []))
        existing_events.update([str(e) for e in new_inc.related_event_ids])
        existing_data['related_event_ids'] = list(existing_events)
        
        # Update Timeline
        existing_timeline = existing_data.get('timeline', [])
        existing_timeline.extend(new_inc.timeline)
        # Sort timeline if it has timestamp
        try:
            existing_timeline = sorted(existing_timeline, key=lambda x: x.get('timestamp', ''))
        except:
            pass
        existing_data['timeline'] = existing_timeline
        
        # Update severity/confidence if higher
        if new_inc.confidence and (not existing_data.get('confidence') or new_inc.confidence > existing_data['confidence']):
            existing_data['confidence'] = new_inc.confidence
            
        existing_db_inc.incident_data = existing_data
        existing_db_inc.status = IncidentStatus.NEW.value # Mark as new to notify analysts of update
        
        return existing_db_inc
