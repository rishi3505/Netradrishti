from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timedelta
from typing import List, Optional
from app.models.database_models import DBSecuritySignal, DBUnifiedSecurityEvent
from app.schemas.signal import SecuritySignal
from app.schemas.event import UnifiedSecurityEvent
from app.core.logging import get_logger

logger = get_logger(__name__)

class CorrelationContext:
    """
    Context for correlation rules. Allows querying of recent signals and events based on dimensions.
    """
    def __init__(self, db: AsyncSession):
        self.db = db
        self._cache_signals = {}
        self._cache_events = {}

    async def get_recent_signals(self, window_minutes: int) -> List[SecuritySignal]:
        cache_key = f"signals_all_{window_minutes}"
        if cache_key in self._cache_signals:
            return self._cache_signals[cache_key]

        now = datetime.utcnow()
        start_time = now - timedelta(minutes=window_minutes)

        query = select(DBSecuritySignal).where(DBSecuritySignal.created_at >= start_time)
        result = await self.db.execute(query)
        db_signals = result.scalars().all()
        
        signals = []
        for db_sig in db_signals:
            try:
                signals.append(SecuritySignal(**db_sig.signal_data))
            except Exception as e:
                logger.error("Failed to parse signal from DB", error=str(e), signal_id=str(db_sig.signal_id))
                
        self._cache_signals[cache_key] = signals
        return signals

    async def get_recent_signals_by_entity(self, entity: str, window_minutes: int) -> List[SecuritySignal]:
        all_signals = await self.get_recent_signals(window_minutes)
        return [sig for sig in all_signals if entity in sig.affected_entities]

    async def get_recent_signals_by_rule(self, rule_id: str, window_minutes: int) -> List[SecuritySignal]:
        all_signals = await self.get_recent_signals(window_minutes)
        return [sig for sig in all_signals if sig.detection_rule_id == rule_id]

    async def get_recent_events(self, window_minutes: int) -> List[UnifiedSecurityEvent]:
        cache_key = f"events_all_{window_minutes}"
        if cache_key in self._cache_events:
            return self._cache_events[cache_key]

        now = datetime.utcnow()
        start_time = now - timedelta(minutes=window_minutes)

        query = select(DBUnifiedSecurityEvent).where(DBUnifiedSecurityEvent.timestamp >= start_time)
        result = await self.db.execute(query)
        db_events = result.scalars().all()
        
        events = []
        for db_event in db_events:
            try:
                events.append(UnifiedSecurityEvent(**db_event.normalized_event))
            except Exception as e:
                logger.error("Failed to parse event from DB", error=str(e), event_id=str(db_event.event_id))
                
        self._cache_events[cache_key] = events
        return events
