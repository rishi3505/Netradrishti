from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime
from enum import Enum
import uuid

class SourceStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    MAINTENANCE = "maintenance"

class SecuritySource(BaseModel):
    source_id: uuid.UUID
    name: str
    source_type: str
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    description: Optional[str] = None
    
    status: SourceStatus = SourceStatus.ACTIVE
    enabled: bool = True
    collector_id: Optional[str] = None
    
    # Exclude sensitive data by not placing it here directly, 
    # or handle in a different model for DB persistence
    # configuration_metadata: Dict[str, Any] = {}
    
    created_at: datetime
    updated_at: datetime
    last_event_received_at: Optional[datetime] = None

class ConnectorMetadata(BaseModel):
    source_type: str
    description: str
    version: str
