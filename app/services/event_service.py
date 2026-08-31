from sqlalchemy.ext.asyncio import AsyncSession
from app.schemas.event import UnifiedSecurityEvent
from app.models.database_models import DBUnifiedSecurityEvent
from app.core.logging import get_logger

logger = get_logger(__name__)

class EventService:
    def __init__(self):
        pass

    async def store_event(self, db: AsyncSession, event: UnifiedSecurityEvent) -> DBUnifiedSecurityEvent:
        logger.info("Storing event in database", event_id=str(event.identity.event_id))
        
        db_event = DBUnifiedSecurityEvent(
            event_id=event.identity.event_id,
            timestamp=event.identity.timestamp,
            ingestion_timestamp=event.identity.ingestion_timestamp,
            source_type=event.source.source_type,
            event_category=event.classification.event_category,
            event_type=event.classification.event_type,
            severity=event.security_context.severity.value if event.security_context and event.security_context.severity else None,
            raw_event=event.raw.model_dump(mode="json"),
            normalized_event=event.model_dump(mode="json")
        )
        
        db.add(db_event)
        await db.commit()
        await db.refresh(db_event)
        
        logger.info("Event successfully stored", event_id=str(event.identity.event_id))
        return db_event

event_service = EventService()
