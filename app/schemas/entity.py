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

class Entity(BaseModel):
    entity_id: UUID = Field(default_factory=uuid4)
    entity_type: EntityType
    aliases: List[str] = Field(default_factory=list)
    identifiers: Dict[str, str] = Field(default_factory=dict)
    attributes: Dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
