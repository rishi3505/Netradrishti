from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Any
from sqlalchemy.ext.asyncio import AsyncSession
from app.schemas.ai_analysis import AIAnalysisRecord, AIProviderConfig
from app.services.ai_analysis.engine import AIAnalysisEngine
from app.repositories.ai_analysis_repository import ai_analysis_repository
from app.repositories.incident_repository import incident_repository
from app.repositories.signal_repository import signal_repository

router = APIRouter()

# Mocking config loader for this module context
def get_ai_config() -> AIProviderConfig:
    return AIProviderConfig(
        enabled=True,
        provider_name="mock",
        model_name="mock-model",
        timeout=30,
        max_tokens=4000,
        external_transmission_enabled=False
    )

async def get_db():
    pass

@router.post("/{incident_id}/ai-analysis", response_model=AIAnalysisRecord)
async def analyze_incident(
    incident_id: str, 
    force_reanalyze: bool = Query(False),
    db: AsyncSession = Depends(get_db)
):
    config = get_ai_config()
    
    # 1. Load context items (mocking some repositories where necessary)
    incident_db = await incident_repository.get(db, incident_id)
    if not incident_db:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    from app.schemas.incident import Incident
    incident = Incident(**incident_db.incident_data)
    
    signals_db = await signal_repository.get_multi(db)
    from app.schemas.signal import SecuritySignal
    signals = [SecuritySignal(**s.signal_data) for s in signals_db if str(s.signal_id) in incident.related_signal_ids]
    
    events = [] # Would pull via event_repository
    attack_graph = {} # Would pull via attack_graph API
    risk_assessment = {} # Would pull via risk API
    
    engine = AIAnalysisEngine(db, config)
    record = await engine.analyze_incident(
        incident=incident,
        signals=signals,
        events=events,
        attack_graph=attack_graph,
        risk_assessment=risk_assessment,
        force_reanalyze=force_reanalyze
    )
    
    return record

@router.get("/{incident_id}/ai-analysis", response_model=AIAnalysisRecord)
async def get_ai_analysis(incident_id: str, db: AsyncSession = Depends(get_db)):
    record = await ai_analysis_repository.get_by_incident_id(db, incident_id)
    if not record:
        raise HTTPException(status_code=404, detail="No AI analysis found for this incident")
    return AIAnalysisRecord(**record.analysis_data)

@router.get("/{incident_id}/ai-analysis/history", response_model=List[AIAnalysisRecord])
async def get_ai_analysis_history(incident_id: str, db: AsyncSession = Depends(get_db)):
    records = await ai_analysis_repository.get_history_by_incident_id(db, incident_id)
    return [AIAnalysisRecord(**r.analysis_data) for r in records]

@router.get("/providers", response_model=List[str])
async def get_providers():
    return ["mock"] # Hardcoded for now based on registry mock setup

@router.post("/providers/{provider_id}/enable")
async def enable_provider(provider_id: str):
    # Would update configuration state
    return {"status": "success", "message": f"Provider {provider_id} enabled."}

@router.post("/providers/{provider_id}/disable")
async def disable_provider(provider_id: str):
    # Would update configuration state
    return {"status": "success", "message": f"Provider {provider_id} disabled."}
