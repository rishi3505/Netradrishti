from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional, List, Any
from app.repositories.base_repository import BaseRepository
from app.models.database_models import DBSecuritySignal
from app.schemas.signal import SecuritySignal

class SignalRepository(BaseRepository[DBSecuritySignal, SecuritySignal, SecuritySignal]):
    def __init__(self):
        super().__init__(DBSecuritySignal)

    async def get(self, db: AsyncSession, id: Any) -> Optional[DBSecuritySignal]:
        query = select(DBSecuritySignal).where(DBSecuritySignal.signal_id == id)
        result = await db.execute(query)
        return result.scalar_one_or_none()

    async def get_multi(self, db: AsyncSession, skip: int = 0, limit: int = 100) -> List[DBSecuritySignal]:
        query = select(DBSecuritySignal).offset(skip).limit(limit)
        result = await db.execute(query)
        return result.scalars().all()

    async def create(self, db: AsyncSession, obj_in: SecuritySignal) -> DBSecuritySignal:
        db_obj = DBSecuritySignal(
            signal_id=obj_in.signal_id,
            signal_type=obj_in.signal_type,
            detection_method=obj_in.detection_method.value if hasattr(obj_in.detection_method, "value") else obj_in.detection_method,
            severity=obj_in.severity.value if hasattr(obj_in.severity, "value") else obj_in.severity,
            signal_data=obj_in.model_dump(mode="json")
        )
        db.add(db_obj)
        await db.commit()
        await db.refresh(db_obj)
        return db_obj

    async def update(self, db: AsyncSession, db_obj: DBSecuritySignal, obj_in: SecuritySignal) -> DBSecuritySignal:
        # We only really update signal_data with the new Pydantic model
        db_obj.signal_data = obj_in.model_dump(mode="json")
        # Update specific columns if needed
        db_obj.severity = obj_in.severity.value if hasattr(obj_in.severity, "value") else obj_in.severity
        await db.commit()
        await db.refresh(db_obj)
        return db_obj

signal_repository = SignalRepository()
