from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.schemas.event import UnifiedSecurityEvent
from app.services.pipeline_service import pipeline_service
from app.services.event_service import event_service
from app.api.dependencies import get_db
from app.models.database_models import DBUnifiedSecurityEvent
import uuid

router = APIRouter()

@router.post("/events", status_code=status.HTTP_201_CREATED)
async def ingest_event(event: UnifiedSecurityEvent, db: AsyncSession = Depends(get_db)):
    try:
        # Pass through processing pipeline
        processed_event = await pipeline_service.process_event(event)
        
        # Store in database
        db_event = await event_service.store_event(db, processed_event)
        
        return {
            "status": "success",
            "message": "Event successfully ingested and processed.",
            "event_id": str(db_event.event_id)
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process event: {str(e)}"
        )

@router.get("/events/{event_id}")
async def get_event(event_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(DBUnifiedSecurityEvent).filter(DBUnifiedSecurityEvent.event_id == event_id))
    db_event = result.scalars().first()
    
    if not db_event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
        
    return db_event.normalized_event
