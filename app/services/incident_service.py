from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from app.schemas.incident import Incident
from app.repositories.incident_repository import incident_repository
from app.models.database_models import DBIncident

class IncidentService:
    def __init__(self):
        self.repository = incident_repository

    async def get_incident(self, db: AsyncSession, incident_id: str) -> Optional[DBIncident]:
        return await self.repository.get(db, incident_id)

    async def list_incidents(self, db: AsyncSession, skip: int = 0, limit: int = 100) -> List[DBIncident]:
        return await self.repository.get_multi(db, skip=skip, limit=limit)

    async def create_incident(self, db: AsyncSession, incident: Incident) -> DBIncident:
        return await self.repository.create(db, incident)
        
    async def update_incident(self, db: AsyncSession, db_incident: DBIncident, incident: Incident) -> DBIncident:
        return await self.repository.update(db, db_incident, incident)

incident_service = IncidentService()
