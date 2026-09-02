from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.schemas.ingestion import IngestionRequest, BatchIngestionRequest, IngestionResult
from app.services.ingestion_service import ingestion_service
from app.api.dependencies import get_db

router = APIRouter()

@router.post("/events", response_model=IngestionResult, status_code=status.HTTP_201_CREATED)
async def ingest_single_event(request: IngestionRequest, db: AsyncSession = Depends(get_db)):
    result = await ingestion_service.ingest_event(request, db)
    if result.status == "failed":
        # we still return 201 or 207 based on REST design, but here returning 400 for single event fail is standard.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.dict()
        )
    return result

@router.post("/events/batch", response_model=IngestionResult, status_code=status.HTTP_207_MULTI_STATUS)
async def ingest_batch_events(request: BatchIngestionRequest, db: AsyncSession = Depends(get_db)):
    result = await ingestion_service.ingest_batch(request, db)
    return result
