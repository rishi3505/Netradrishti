from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from uuid import UUID, uuid4
from enum import Enum

class EntityType(str, Enum):
    USER = "user"
    HOST = "host"
    IP = "ip"
    DOMAIN = "domain"
    FILE = "file"
    PROCESS = "process"
    CLOUD_RESOURCE = "cloud_resource"
    ACCOUNT = "account"

class EntityAlias(BaseModel):
    alias_value: str
    alias_type: str
    normalized_value: str
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    source: str

class EntityIdentifier(BaseModel):
    identifier_type: str
    value: str
    normalized_value: str
    confidence: int
    source: str
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)

class EntityRelationship(BaseModel):
    source_entity_id: UUID
    target_entity_id: UUID
    relationship_type: str
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)

class Entity(BaseModel):
    entity_id: UUID = Field(default_factory=uuid4)
    entity_type: EntityType
    value: str
    normalized_value: str
    aliases: List[EntityAlias] = Field(default_factory=list)
    identifiers: List[EntityIdentifier] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)

class ExtractedEntity(BaseModel):
    entity_type: EntityType
    value: str
    normalized_value: str
    source_event_id: UUID
    attributes: Dict[str, Any] = Field(default_factory=dict)
    confidence: int = 100

class EntityResolutionResult(BaseModel):
    canonical_entity: Entity
    resolution_confidence: int
    resolution_reasons: List[str]
    matching_identifiers: List[str]
    is_new: bool = False
