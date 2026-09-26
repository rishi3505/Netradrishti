from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional, List, Any
import uuid
from app.repositories.base_repository import BaseRepository
from app.models.database_models import DBRiskAssessment
from app.schemas.attack_graph import RiskAssessment

class RiskAssessmentRepository(BaseRepository[DBRiskAssessment, RiskAssessment, RiskAssessment]):
    def __init__(self):
        super().__init__(DBRiskAssessment)

    async def get_by_incident_id(self, db: AsyncSession, incident_id: str) -> Optional[DBRiskAssessment]:
        # Gets the most recent risk assessment for an incident
        query = select(DBRiskAssessment).where(
            DBRiskAssessment.incident_id == incident_id
        ).order_by(DBRiskAssessment.calculated_at.desc())
        result = await db.execute(query)
        return result.scalar_one_or_none()

    async def get_history_by_incident_id(self, db: AsyncSession, incident_id: str) -> List[DBRiskAssessment]:
        query = select(DBRiskAssessment).where(
            DBRiskAssessment.incident_id == incident_id
        ).order_by(DBRiskAssessment.calculated_at.desc())
        result = await db.execute(query)
        return result.scalars().all()

    async def create(self, db: AsyncSession, obj_in: RiskAssessment) -> DBRiskAssessment:
        db_obj = DBRiskAssessment(
            assessment_id=obj_in.assessment_id,
            incident_id=obj_in.incident_id,
            risk_score=str(obj_in.risk_score),
            risk_level=obj_in.risk_level.value if hasattr(obj_in.risk_level, "value") else obj_in.risk_level,
            assessment_data=obj_in.model_dump(mode="json")
        )
        db.add(db_obj)
        await db.commit()
        await db.refresh(db_obj)
        return db_obj

risk_assessment_repository = RiskAssessmentRepository()
