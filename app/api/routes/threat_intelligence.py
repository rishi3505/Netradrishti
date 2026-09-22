from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.dependencies import get_db
from app.schemas.threat_intel import (
    ThreatIntelligenceRequest,
    BatchThreatIntelligenceRequest,
    ThreatIntelligenceResult,
    ProviderHealthStatus
)
from app.services.threat_intelligence.engine import engine
from app.services.threat_intelligence.enrichment import enrichment_service
from app.services.threat_intelligence.registry import registry
from app.models.database_models import DBThreatIntelligence, DBIncidentIntelligence
from sqlalchemy import select

router = APIRouter(prefix="/threat-intelligence", tags=["Threat Intelligence"])

@router.post("/lookup", response_model=ThreatIntelligenceResult)
async def lookup_indicator(request: ThreatIntelligenceRequest):
    result = await engine.process_indicator(request)
    return result

@router.post("/lookup/batch", response_model=List[ThreatIntelligenceResult])
async def lookup_batch(request: BatchThreatIntelligenceRequest):
    reqs = [ThreatIntelligenceRequest(indicator=ind) for ind in request.indicators]
    results = await engine.process_batch(reqs)
    return results

@router.get("/{indicator_type}/{indicator}", response_model=ThreatIntelligenceResult)
async def get_indicator_intelligence(indicator_type: str, indicator: str):
    request = ThreatIntelligenceRequest(indicator=indicator)
    result = await engine.process_indicator(request)
    return result

@router.post("/enrich/incident/{incident_id}", response_model=List[ThreatIntelligenceResult])
async def enrich_incident(incident_id: UUID, db: AsyncSession = Depends(get_db)):
    results = await enrichment_service.enrich_incident(db, incident_id)
    return results

@router.get("/incidents/{incident_id}", response_model=List[ThreatIntelligenceResult])
async def get_incident_intelligence(incident_id: UUID, db: AsyncSession = Depends(get_db)):
    query = (
        select(DBThreatIntelligence)
        .join(DBIncidentIntelligence, DBThreatIntelligence.id == DBIncidentIntelligence.threat_intel_id)
        .where(DBIncidentIntelligence.incident_id == incident_id)
    )
    result = await db.execute(query)
    db_tis = result.scalars().all()
    
    return [ThreatIntelligenceResult(**ti.intelligence_data) for ti in db_tis]

@router.get("/providers", response_model=List[str])
async def list_providers():
    return [p.name for p in registry.get_all_providers()]

@router.get("/providers/{provider_id}/health", response_model=ProviderHealthStatus)
async def check_provider_health(provider_id: str):
    provider = registry.get_provider(provider_id)
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    return await provider.health_check()
