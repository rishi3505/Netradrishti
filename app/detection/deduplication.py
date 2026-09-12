from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timedelta
from app.models.database_models import DBSecuritySignal
from app.schemas.signal import SecuritySignal
from typing import Optional

class SignalDeduplicator:
    """
    Prevents duplicate signals by finding recent similar signals.
    """
    def __init__(self, db: AsyncSession):
        self.db = db

    async def find_duplicate(self, signal: SecuritySignal, window_minutes: int = 60) -> Optional[DBSecuritySignal]:
        """
        Looks for a recent signal from the same rule affecting the same key entities.
        """
        now = datetime.utcnow()
        start_time = now - timedelta(minutes=window_minutes)
        
        # Simple heuristic: same rule ID and at least one overlapping entity
        query = select(DBSecuritySignal).where(
            DBSecuritySignal.created_at >= start_time
        ).where(
            DBSecuritySignal.signal_data.op('->>')('detection_rule_id') == signal.detection_rule_id
        )
        
        result = await self.db.execute(query)
        recent_signals = result.scalars().all()
        
        for db_sig in recent_signals:
            sig_data = db_sig.signal_data
            db_entities = set(sig_data.get('affected_entities', []))
            new_entities = set(signal.affected_entities)
            
            if len(db_entities.intersection(new_entities)) > 0:
                # We found a recent signal for the same rule and overlapping entities
                return db_sig
                
        return None
        
    async def merge_signals(self, existing_db_signal: DBSecuritySignal, new_signal: SecuritySignal) -> DBSecuritySignal:
        """
        Merges new signal evidence into the existing signal.
        """
        existing_data = existing_db_signal.signal_data
        
        # Merge related events
        existing_events = set(existing_data.get('related_event_ids', []))
        existing_events.update([str(e) for e in new_signal.related_event_ids])
        existing_data['related_event_ids'] = list(existing_events)
        
        # Update confidence if higher
        if new_signal.confidence and (not existing_data.get('confidence') or new_signal.confidence > existing_data['confidence']):
            existing_data['confidence'] = new_signal.confidence
            existing_data['risk_score'] = new_signal.risk_score
            
        # Add to evidence count
        if 'occurrences' not in existing_data.get('evidence', {}):
            if existing_data.get('evidence') is None:
                existing_data['evidence'] = {}
            existing_data['evidence']['occurrences'] = 1
        existing_data['evidence']['occurrences'] += 1
        
        existing_db_signal.signal_data = existing_data
        return existing_db_signal
