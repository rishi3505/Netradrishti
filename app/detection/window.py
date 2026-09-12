from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from datetime import datetime, timedelta
from typing import List, Optional
from uuid import UUID
from app.models.database_models import DBUnifiedSecurityEvent
from app.schemas.event import UnifiedSecurityEvent
from app.core.logging import get_logger

logger = get_logger(__name__)

class EventWindow:
    """
    Retrieves events within a specific time window for detection rules.
    """
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_recent_events(
        self,
        time_window_minutes: int,
        event_category: Optional[str] = None,
        event_type: Optional[str] = None
    ) -> List[UnifiedSecurityEvent]:
        """
        Fetch events from the database within the specified time window.
        """
        now = datetime.utcnow()
        start_time = now - timedelta(minutes=time_window_minutes)

        query = select(DBUnifiedSecurityEvent).where(
            DBUnifiedSecurityEvent.timestamp >= start_time
        )
        
        if event_category:
            query = query.where(DBUnifiedSecurityEvent.event_category == event_category)
        if event_type:
            query = query.where(DBUnifiedSecurityEvent.event_type == event_type)
            
        result = await self.db.execute(query)
        db_events = result.scalars().all()
        
        events = []
        for db_event in db_events:
            try:
                # DB stores normalized_event as a dict, we need to parse it
                events.append(UnifiedSecurityEvent(**db_event.normalized_event))
            except Exception as e:
                logger.error("Failed to parse event from database", error=str(e), event_id=str(db_event.event_id))
        
        return events
