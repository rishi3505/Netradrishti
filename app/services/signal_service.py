from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from app.schemas.signal import SecuritySignal
from app.repositories.signal_repository import signal_repository
from app.models.database_models import DBSecuritySignal

class SignalService:
    def __init__(self):
        self.repository = signal_repository

    async def get_signal(self, db: AsyncSession, signal_id: str) -> Optional[DBSecuritySignal]:
        return await self.repository.get(db, signal_id)

    async def list_signals(self, db: AsyncSession, skip: int = 0, limit: int = 100) -> List[DBSecuritySignal]:
        return await self.repository.get_multi(db, skip=skip, limit=limit)

    async def create_signal(self, db: AsyncSession, signal: SecuritySignal) -> DBSecuritySignal:
        return await self.repository.create(db, signal)

signal_service = SignalService()
