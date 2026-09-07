from datetime import datetime
from sqlalchemy.orm import Session
from app.schemas.event import UnifiedSecurityEvent
from app.schemas.normalized_event import NormalizedEvent, NormalizationMetadata
from app.normalization.engine import NormalizationEngine
from app.entities.extractor import EntityExtractor
from app.services.entity_service import EntityService

class NormalizationPipeline:
    def __init__(self, db: Session):
        self.engine = NormalizationEngine()
        self.extractor = EntityExtractor()
        self.entity_service = EntityService(db)

    def process_event(self, event: UnifiedSecurityEvent) -> NormalizedEvent:
        # 1. Normalize
        normalized_event, warnings = self.engine.normalize_event(event)
        
        metadata = NormalizationMetadata(
            status="normalized_with_warnings" if warnings else "normalized",
            normalized_at=datetime.utcnow(),
            warnings=warnings
        )
        
        # 2. Extract Entities
        extracted_entities = self.extractor.extract(normalized_event)
        
        # 3. Resolve Entities
        resolution_results = []
        for ext in extracted_entities:
            result = self.entity_service.resolve_entity(ext)
            resolution_results.append(result)
            
        return NormalizedEvent(
            event=normalized_event,
            normalization=metadata,
            entities=resolution_results
        )
