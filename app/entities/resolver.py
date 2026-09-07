from typing import List, Optional
from app.schemas.entity import ExtractedEntity, Entity, EntityResolutionResult
from .matcher import EntityMatcher

class EntityResolver:
    def __init__(self, repository):
        self.matcher = EntityMatcher()
        self.repository = repository # will be EntityRepository

    def resolve(self, extracted: ExtractedEntity) -> EntityResolutionResult:
        # Get candidates from repository
        # For simplicity, we assume repo can find by normalized_value or IP
        candidates = self.repository.find_candidates(extracted)
        
        best_candidate = None
        highest_score = 0
        best_reasons = []
        
        for candidate in candidates:
            score, reasons = self.matcher.match(extracted, candidate)
            if score > highest_score:
                highest_score = score
                best_candidate = candidate
                best_reasons = reasons
                
        # Determine threshold
        if highest_score >= 70:
            # Strong match -> merge/link
            return EntityResolutionResult(
                canonical_entity=best_candidate,
                resolution_confidence=highest_score,
                resolution_reasons=best_reasons,
                matching_identifiers=[extracted.normalized_value],
                is_new=False
            )
            
        # Else create new entity
        new_entity = Entity(
            entity_type=extracted.entity_type,
            value=extracted.value,
            normalized_value=extracted.normalized_value,
            attributes=extracted.attributes
        )
        # Store in DB
        new_entity = self.repository.create(new_entity)
        
        return EntityResolutionResult(
            canonical_entity=new_entity,
            resolution_confidence=100,
            resolution_reasons=["New Entity Created"],
            matching_identifiers=[extracted.normalized_value],
            is_new=True
        )
