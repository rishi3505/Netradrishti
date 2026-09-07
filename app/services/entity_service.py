from sqlalchemy.orm import Session
from app.entities.resolver import EntityResolver
from app.repositories.entity_repository import EntityRepository
from app.schemas.entity import ExtractedEntity, EntityResolutionResult

class EntityService:
    def __init__(self, db: Session):
        self.repository = EntityRepository(db)
        self.resolver = EntityResolver(self.repository)

    def resolve_entity(self, extracted: ExtractedEntity) -> EntityResolutionResult:
        return self.resolver.resolve(extracted)
