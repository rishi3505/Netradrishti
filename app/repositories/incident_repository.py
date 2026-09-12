from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional, List, Any
from app.repositories.base_repository import BaseRepository
from app.models.database_models import DBIncident
from app.schemas.incident import Incident

class IncidentRepository(BaseRepository[DBIncident, Incident, Incident]):
    def __init__(self):
        super().__init__(DBIncident)

    async def get(self, db: AsyncSession, id: Any) -> Optional[DBIncident]:
        query = select(DBIncident).where(DBIncident.incident_id == id)
        result = await db.execute(query)
        return result.scalar_one_or_none()

    async def get_multi(self, db: AsyncSession, skip: int = 0, limit: int = 100) -> List[DBIncident]:
        query = select(DBIncident).offset(skip).limit(limit)
        result = await db.execute(query)
        return result.scalars().all()

    async def create(self, db: AsyncSession, obj_in: Incident) -> DBIncident:
        db_obj = DBIncident(
            incident_id=obj_in.incident_id,
            title=obj_in.title,
            status=obj_in.status.value if hasattr(obj_in.status, "value") else obj_in.status,
            severity=obj_in.severity.value if hasattr(obj_in.severity, "value") else obj_in.severity,
            incident_data=obj_in.model_dump(mode="json")
        )
        db.add(db_obj)
        await db.commit()
        await db.refresh(db_obj)
        return db_obj

    async def update(self, db: AsyncSession, db_obj: DBIncident, obj_in: Incident) -> DBIncident:
        db_obj.incident_data = obj_in.model_dump(mode="json")
        db_obj.status = obj_in.status.value if hasattr(obj_in.status, "value") else obj_in.status
        db_obj.severity = obj_in.severity.value if hasattr(obj_in.severity, "value") else obj_in.severity
        await db.commit()
        await db.refresh(db_obj)
        return db_obj

incident_repository = IncidentRepository()
