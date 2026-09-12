from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from app.schemas.normalized_event import NormalizedEvent
from app.schemas.signal import SecuritySignal
from app.detection.engine import DetectionEngine
from app.detection.context import DetectionContext
from app.detection.window import EventWindow
from app.core.logging import get_logger

logger = get_logger(__name__)

class DetectionPipeline:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.engine = DetectionEngine()
        self.window = EventWindow(db)

    async def process_event(self, event: NormalizedEvent) -> List[SecuritySignal]:
        """
        Main entry point for detection.
        Takes a normalized event, creates a context, and runs it through the engine.
        """
        logger.info("Starting detection pipeline", event_id=str(event.event.identity.event_id))
        context = DetectionContext(event, self.window)
        signals = await self.engine.analyze_event(event, context)
        
        if signals:
            logger.info("Detection pipeline generated signals", count=len(signals), event_id=str(event.event.identity.event_id))
            
        return signals
