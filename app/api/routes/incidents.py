from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from app.core.database import get_db
from app.services.incident_service import incident_service
from app.schemas.incident import Incident
from app.core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/incidents", tags=["Incidents"])

@router.get("", response_model=List[Incident])
async def list_incidents(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db)
):
    """
    List generated security incidents.
    """
    db_incidents = await incident_service.list_incidents(db, skip=skip, limit=limit)
    return [Incident(**inc.incident_data) for inc in db_incidents]

@router.get("/{incident_id}", response_model=Incident)
async def get_incident(incident_id: str, db: AsyncSession = Depends(get_db)):
    """
    Get a specific incident by ID.
    """
    db_inc = await incident_service.get_incident(db, incident_id)
    if not db_inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return Incident(**db_inc.incident_data)

@router.get("/{incident_id}/timeline")
async def get_incident_timeline(incident_id: str, db: AsyncSession = Depends(get_db)):
    """
    Get the timeline of an incident.
    """
    db_inc = await incident_service.get_incident(db, incident_id)
    if not db_inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    incident = Incident(**db_inc.incident_data)
    return incident.timeline
