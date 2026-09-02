from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
from uuid import UUID

class IngestionRequest(BaseModel):
    source_type: str = Field(..., description="The type of the source (e.g. windows, firewall, suricata)")
    raw_event: Dict[str, Any] = Field(..., description="The raw source-specific event data")

class BatchIngestionRequest(BaseModel):
    source_type: str = Field(..., description="The type of the source")
    events: List[Dict[str, Any]] = Field(..., description="A list of raw events")

class IngestionResult(BaseModel):
    ingestion_id: str
    source_id: Optional[str] = None
    source_type: str
    status: str
    events_received: int
    events_processed: int
    events_failed: int
    processed_event_ids: List[str] = []
    errors: List[Dict[str, Any]] = []
    started_at: datetime
    completed_at: datetime
