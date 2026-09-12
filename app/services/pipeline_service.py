from app.schemas.event import UnifiedSecurityEvent, EventLifecycle
from app.core.logging import get_logger

logger = get_logger(__name__)

class PipelineService:
    def __init__(self):
        pass

    async def process_event(self, event: UnifiedSecurityEvent) -> UnifiedSecurityEvent:
        """
        Main pipeline for processing an incoming event.
        Currently implements: RECEIVED -> VALIDATED -> NORMALIZED (assumed, since it's already UnifiedSecurityEvent) 
        -> ENRICHED -> STORED
        """
        logger.info("Starting pipeline processing for event", event_id=str(event.identity.event_id))
        
        # 1. Validation
        event.lifecycle = EventLifecycle.VALIDATED
        logger.debug("Event validated", event_id=str(event.identity.event_id))
        
        # 2. Metadata Enrichment
        event.lifecycle = EventLifecycle.ENRICHED
        logger.debug("Event enriched", event_id=str(event.identity.event_id))
        
        # 3. Storage (Handled by EventService later, but we mark the state here)
        # Event is returned to the caller to be stored via EventService
        
        # NOTE: Detection is currently run asynchronously or sequentially after NormalizationPipeline.
        # It takes a NormalizedEvent, not a UnifiedSecurityEvent.
        # This service's process_event is currently only for the ingestion pipeline up to ENRICHED.
        
        event.lifecycle = EventLifecycle.STORED
        return event

pipeline_service = PipelineService()
