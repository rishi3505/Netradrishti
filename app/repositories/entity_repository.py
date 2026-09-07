from sqlalchemy.orm import Session
from typing import List, Optional
from app.models.entity_models import EntityModel, EntityIdentifierModel
from app.schemas.entity import Entity, ExtractedEntity

class EntityRepository:
    def __init__(self, db_session: Session):
        self.db = db_session

    def create(self, entity: Entity) -> Entity:
        db_entity = EntityModel(
            entity_id=entity.entity_id,
            entity_type=entity.entity_type,
            value=entity.value,
            normalized_value=entity.normalized_value,
            attributes=entity.attributes,
            first_seen=entity.first_seen,
            last_seen=entity.last_seen
        )
        self.db.add(db_entity)
        self.db.commit()
        self.db.refresh(db_entity)
        return self._to_schema(db_entity)
        
    def find_candidates(self, extracted: ExtractedEntity) -> List[Entity]:
        """
        Finds entities in DB that could match the extracted entity
        Looks for matches on normalized_value across entities of the same type.
        For advanced matching, this could join on identifiers.
        """
        query = self.db.query(EntityModel).filter(
            EntityModel.entity_type == extracted.entity_type,
            EntityModel.normalized_value == extracted.normalized_value
        )
        
        candidates = query.limit(50).all()
        return [self._to_schema(c) for c in candidates]

    def _to_schema(self, db_obj: EntityModel) -> Entity:
        return Entity(
            entity_id=db_obj.entity_id,
            entity_type=db_obj.entity_type,
            value=db_obj.value,
            normalized_value=db_obj.normalized_value,
            attributes=db_obj.attributes,
            first_seen=db_obj.first_seen,
            last_seen=db_obj.last_seen
        )
