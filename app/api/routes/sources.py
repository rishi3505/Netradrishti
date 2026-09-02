from fastapi import APIRouter, HTTPException, status
from typing import List, Dict, Any
import uuid
from app.schemas.source import SecuritySource, ConnectorMetadata
from app.services.source_service import source_service
from app.connectors.registry import connector_registry
from app.connectors.exceptions import ConnectorNotFoundError

router = APIRouter()

@router.get("/", response_model=List[SecuritySource])
async def list_sources():
    return source_service.list_sources()

@router.get("/connectors", response_model=List[ConnectorMetadata])
async def list_connectors():
    metadata = connector_registry.list_connectors()
    return [ConnectorMetadata(**meta) for meta in metadata.values()]

@router.get("/{source_id}", response_model=SecuritySource)
async def get_source(source_id: uuid.UUID):
    source = source_service.get_source(source_id)
    if not source:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Source not found")
    return source

@router.get("/connectors/{source_type}/health")
async def connector_health(source_type: str):
    try:
        connector = connector_registry.get_connector(source_type)
        is_healthy = connector.health_check()
        return {"source_type": source_type, "status": "healthy" if is_healthy else "unhealthy"}
    except ConnectorNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
