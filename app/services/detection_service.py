from sqlalchemy.ext.asyncio import AsyncSession
from app.schemas.normalized_event import NormalizedEvent
from app.schemas.signal import SecuritySignal
from app.detection.pipeline import DetectionPipeline
from app.detection.deduplication import SignalDeduplicator
from app.services.signal_service import signal_service
from app.core.logging import get_logger

logger = get_logger(__name__)

class DetectionService:
    def __init__(self):
        pass

    async def process_detection(self, db: AsyncSession, event: NormalizedEvent):
        """
        Runs the detection pipeline and persists any resulting signals.
        """
        logger.info("Running detection for event", event_id=str(event.event.identity.event_id))
        
        pipeline = DetectionPipeline(db)
        deduplicator = SignalDeduplicator(db)
        
        # 1. Run engine to get candidate signals
        signals = await pipeline.process_event(event)
        
        for signal in signals:
            try:
                # 2. Deduplication check
                duplicate_db_sig = await deduplicator.find_duplicate(signal)
                
                if duplicate_db_sig:
                    # Update existing signal
                    logger.info("Found duplicate signal, merging", signal_id=str(duplicate_db_sig.signal_id))
                    merged_db_sig = await deduplicator.merge_signals(duplicate_db_sig, signal)
                    await db.commit()
                else:
                    # Create new signal
                    logger.info("Creating new signal", rule_id=signal.detection_rule_id)
                    await signal_service.create_signal(db, signal)
            except Exception as e:
                logger.error("Failed to process signal", error=str(e), rule_id=signal.detection_rule_id)

detection_service = DetectionService()
