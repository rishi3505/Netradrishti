from typing import List, Optional
import uuid
from datetime import datetime
from app.schemas.source import SecuritySource, SourceStatus
from app.connectors.registry import connector_registry

# In-memory store for sources for Module 2
_mock_sources = {}

class SourceService:
    def create_source(self, source_data: dict) -> SecuritySource:
        source_id = uuid.uuid4()
        source = SecuritySource(
            source_id=source_id,
            **source_data,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        _mock_sources[source_id] = source
        return source

    def get_source(self, source_id: uuid.UUID) -> Optional[SecuritySource]:
        return _mock_sources.get(source_id)

    def list_sources(self) -> List[SecuritySource]:
        return list(_mock_sources.values())

    def update_source_status(self, source_id: uuid.UUID, status: SourceStatus) -> Optional[SecuritySource]:
        source = self.get_source(source_id)
        if source:
            source.status = status
            source.updated_at = datetime.utcnow()
            return source
        return None

source_service = SourceService()
