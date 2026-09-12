from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from app.core.database import get_db
from app.services.signal_service import signal_service
from app.schemas.signal import SecuritySignal
from app.core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/signals", tags=["Signals"])

@router.get("", response_model=List[SecuritySignal])
async def list_signals(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db)
):
    """
    List generated security signals.
    """
    db_signals = await signal_service.list_signals(db, skip=skip, limit=limit)
    return [SecuritySignal(**sig.signal_data) for sig in db_signals]

@router.get("/{signal_id}", response_model=SecuritySignal)
async def get_signal(signal_id: str, db: AsyncSession = Depends(get_db)):
    """
    Get a specific signal by ID.
    """
    db_signal = await signal_service.get_signal(db, signal_id)
    if not db_signal:
        raise HTTPException(status_code=404, detail="Signal not found")
    return SecuritySignal(**db_signal.signal_data)
