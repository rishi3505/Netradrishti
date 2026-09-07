from fastapi import APIRouter, Depends
from typing import List
from sqlalchemy.orm import Session
from app.api.dependencies import get_db
from app.schemas.entity import ExtractedEntity, EntityResolutionResult
from app.services.entity_service import EntityService

router = APIRouter(prefix="/api/v1/entities", tags=["Entities"])

@router.post("/resolve", response_model=EntityResolutionResult)
def preview_resolution(entity: ExtractedEntity, db: Session = Depends(get_db)):
    """Preview entity resolution matches"""
    service = EntityService(db)
    return service.resolve_entity(entity)
