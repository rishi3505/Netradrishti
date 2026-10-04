from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import Dict, Any, List
import uuid

from app.core.database import get_db
from app.core.auth import require_role
from app.models.database_models import DBIncident, DBEntity, DBSecuritySignal

router = APIRouter(prefix="/api/v1", tags=["Search and Entities"])

@router.get("/search")
def global_search(
    q: str = Query(..., min_length=3),
    db: Session = Depends(get_db),
    user: Dict = Depends(require_role(["ANALYST", "RESPONDER", "ADMIN"]))
) -> Dict[str, Any]:
    
    # Very basic search implementation
    search_term = f"%{q}%"
    
    incidents = db.query(DBIncident).filter(
        or_(DBIncident.title.ilike(search_term), DBIncident.incident_id.cast(str).ilike(search_term))
    ).limit(10).all()

    entities = db.query(DBEntity).filter(
        DBEntity.entity_data.cast(str).ilike(search_term)
    ).limit(10).all()

    return {
        "incidents": [inc.incident_data for inc in incidents],
        "entities": [ent.entity_data for ent in entities],
        "query": q
    }

@router.get("/entities/{entity_id}/investigate")
def investigate_entity(
    entity_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: Dict = Depends(require_role(["ANALYST", "RESPONDER", "ADMIN"]))
) -> Dict[str, Any]:
    
    entity = db.query(DBEntity).filter(DBEntity.entity_id == entity_id).first()
    if not entity:
        return {"error": "Entity not found"}
        
    # Mocking related incidents logic for demo
    related_incidents = db.query(DBIncident).limit(5).all()

    return {
        "entity": entity.entity_data,
        "related_incidents": [inc.incident_data for inc in related_incidents]
    }
