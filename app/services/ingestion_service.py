from typing import Dict, Any, List
import uuid
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from app.connectors.registry import connector_registry
from app.connectors.exceptions import ConnectorNotFoundError, ValidationError, TransformationError
from app.schemas.ingestion import IngestionRequest, BatchIngestionRequest, IngestionResult
from app.schemas.event import UnifiedSecurityEvent
from app.services.pipeline_service import pipeline_service
from app.services.event_service import event_service
from app.core.logging import get_logger

logger = get_logger(__name__)

class IngestionService:
    
    async def ingest_event(self, request: IngestionRequest, db: AsyncSession = None) -> IngestionResult:
        ingestion_id = str(uuid.uuid4())
        started_at = datetime.utcnow()
        
        try:
            connector = connector_registry.get_connector(request.source_type)
        except ConnectorNotFoundError as e:
            return self._build_result(ingestion_id, request.source_type, "failed", 1, 0, 1, [], [{"error": str(e)}], started_at)
            
        try:
            unified_event = connector.transform(request.raw_event)
            processed_event = await pipeline_service.process_event(unified_event)
            
            if db:
                await event_service.store_event(db, processed_event)
            
            return self._build_result(ingestion_id, request.source_type, "completed", 1, 1, 0, [str(processed_event.identity.event_id)], [], started_at)
        except (ValidationError, TransformationError) as e:
            logger.error(f"Event transformation error: {str(e)}")
            return self._build_result(ingestion_id, request.source_type, "failed", 1, 0, 1, [], [{"error": str(e)}], started_at)
        except Exception as e:
            logger.error(f"Unexpected pipeline error: {str(e)}")
            return self._build_result(ingestion_id, request.source_type, "failed", 1, 0, 1, [], [{"error": f"Internal error: {str(e)}"}], started_at)
            
    async def ingest_batch(self, request: BatchIngestionRequest, db: AsyncSession = None) -> IngestionResult:
        ingestion_id = str(uuid.uuid4())
        started_at = datetime.utcnow()
        total = len(request.events)
        
        try:
            connector = connector_registry.get_connector(request.source_type)
        except ConnectorNotFoundError as e:
            return self._build_result(ingestion_id, request.source_type, "failed", total, 0, total, [], [{"error": str(e)}], started_at)
            
        processed_ids = []
        errors = []
        
        for idx, raw_event in enumerate(request.events):
            try:
                unified_event = connector.transform(raw_event)
                processed_event = await pipeline_service.process_event(unified_event)
                
                if db:
                    await event_service.store_event(db, processed_event)
                    
                processed_ids.append(str(processed_event.identity.event_id))
            except (ValidationError, TransformationError) as e:
                errors.append({"index": idx, "error": str(e)})
            except Exception as e:
                errors.append({"index": idx, "error": f"Internal error: {str(e)}"})
                
        failed = len(errors)
        processed = total - failed
        status = "completed" if failed == 0 else "partially_completed" if processed > 0 else "failed"
        
        return self._build_result(ingestion_id, request.source_type, status, total, processed, failed, processed_ids, errors, started_at)

    def _build_result(self, ingestion_id, source_type, status, received, processed, failed, processed_ids, errors, started_at) -> IngestionResult:
        return IngestionResult(
            ingestion_id=ingestion_id,
            source_type=source_type,
            status=status,
            events_received=received,
            events_processed=processed,
            events_failed=failed,
            processed_event_ids=processed_ids,
            errors=errors,
            started_at=started_at,
            completed_at=datetime.utcnow()
        )

ingestion_service = IngestionService()
