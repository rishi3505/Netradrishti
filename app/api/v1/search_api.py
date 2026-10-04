from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_, cast, String
from typing import Dict, Any, List
import uuid

from app.api.dependencies import get_db
from app.core.auth import require_role
from app.models.database_models import DBIncident, DBEntity

router = APIRouter(prefix="/api/v1", tags=["Search and Entities"])

@router.get("/search")
async def global_search(
    q: str = Query(..., min_length=3),
    db: AsyncSession = Depends(get_db),
    user: Dict = Depends(require_role(["ANALYST", "RESPONDER", "ADMIN"]))
) -> Dict[str, Any]:

    search_term = f"%{q}%"

    inc_result = await db.execute(
        select(DBIncident).filter(
            or_(
                DBIncident.title.ilike(search_term),
                cast(DBIncident.incident_id, String).ilike(search_term)
            )
        ).limit(10)
    )
    incidents = inc_result.scalars().all()

    ent_result = await db.execute(
        select(DBEntity).filter(
            cast(DBEntity.entity_data, String).ilike(search_term)
        ).limit(10)
    )
    entities = ent_result.scalars().all()

    return {
        "incidents": [inc.incident_data for inc in incidents],
        "entities": [ent.entity_data for ent in entities],
        "query": q
    }

@router.get("/entities/{entity_id}/investigate")
async def investigate_entity(
    entity_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: Dict = Depends(require_role(["ANALYST", "RESPONDER", "ADMIN"]))
) -> Dict[str, Any]:

    ent_result = await db.execute(
        select(DBEntity).filter(DBEntity.entity_id == entity_id)
    )
    entity = ent_result.scalar_one_or_none()
    if not entity:
        return {"error": "Entity not found"}

    inc_result = await db.execute(select(DBIncident).limit(5))
    related_incidents = inc_result.scalars().all()

    return {
        "entity": entity.entity_data,
        "related_incidents": [inc.incident_data for inc in related_incidents]
    }
