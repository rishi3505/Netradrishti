from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from typing import Optional, List, Any
import uuid
from app.repositories.base_repository import BaseRepository
from app.models.database_models import DBAIAnalysis
from app.schemas.ai_analysis import AIAnalysisRecord

class AIAnalysisRepository(BaseRepository[DBAIAnalysis, AIAnalysisRecord, AIAnalysisRecord]):
    def __init__(self):
        super().__init__(DBAIAnalysis)

    async def get_by_incident_id(self, db: AsyncSession, incident_id: str) -> Optional[DBAIAnalysis]:
        query = select(DBAIAnalysis).where(
            DBAIAnalysis.incident_id == incident_id
        ).order_by(DBAIAnalysis.created_at.desc())
        result = await db.execute(query)
        return result.scalar_one_or_none()

    async def get_history_by_incident_id(self, db: AsyncSession, incident_id: str) -> List[DBAIAnalysis]:
        query = select(DBAIAnalysis).where(
            DBAIAnalysis.incident_id == incident_id
        ).order_by(DBAIAnalysis.created_at.desc())
        result = await db.execute(query)
        return result.scalars().all()
        
    async def get_by_incident_and_hash(self, db: AsyncSession, incident_id: str, context_hash: str) -> Optional[DBAIAnalysis]:
        query = select(DBAIAnalysis).where(
            and_(
                DBAIAnalysis.incident_id == incident_id,
                DBAIAnalysis.context_hash == context_hash
            )
        ).order_by(DBAIAnalysis.created_at.desc())
        result = await db.execute(query)
        return result.scalar_one_or_none()

    async def create(self, db: AsyncSession, obj_in: AIAnalysisRecord) -> DBAIAnalysis:
        db_obj = DBAIAnalysis(
            analysis_id=obj_in.analysis_id,
            incident_id=obj_in.incident_id,
            context_hash=obj_in.context_hash,
            provider=obj_in.provider,
            status=obj_in.status.value if hasattr(obj_in.status, "value") else obj_in.status,
            analysis_data=obj_in.model_dump(mode="json")
        )
        db.add(db_obj)
        await db.commit()
        await db.refresh(db_obj)
        return db_obj

    async def update(self, db: AsyncSession, db_obj: DBAIAnalysis, obj_in: AIAnalysisRecord) -> DBAIAnalysis:
        db_obj.analysis_data = obj_in.model_dump(mode="json")
        db_obj.status = obj_in.status.value if hasattr(obj_in.status, "value") else obj_in.status
        await db.commit()
        await db.refresh(db_obj)
        return db_obj

ai_analysis_repository = AIAnalysisRepository()
