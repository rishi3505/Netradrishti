from fastapi import APIRouter, Depends, HTTPException
from typing import List, Any
from sqlalchemy.ext.asyncio import AsyncSession
from app.repositories.attack_graph_repository import attack_graph_node_repository, attack_graph_edge_repository
from app.repositories.risk_repository import risk_assessment_repository
from app.repositories.incident_repository import incident_repository
from app.repositories.signal_repository import signal_repository
from app.services.attack_risk.risk.engine import RiskEngine
from app.services.attack_risk.graph.builder import AttackGraphBuilder
from app.schemas.attack_graph import RiskAssessment, AttackGraphNode, AttackGraphEdge, AttackPath

# Assuming some get_db dependency exists. We will mock import it or define it.
# Usually it's in app.core.database or app.api.deps. For now, assuming a generic dependency.
# from app.api.deps import get_db

router = APIRouter()

# Stub for db dependency (will need to align with actual project structure)
async def get_db():
    pass # Replace with actual dependency

@router.get("/{incident_id}/attack-graph", response_model=dict)
async def get_attack_graph(incident_id: str, db: AsyncSession = Depends(get_db)):
    nodes_db = await attack_graph_node_repository.get_multi(db) # Should be filtered by incident in reality
    # For simplicity of this module implementation, we assume a custom method exists to pull incident subgraph.
    # We will just fetch the incident node and edges
    
    incident_node = await attack_graph_node_repository.get_by_node_id(db, f"incident-{incident_id}")
    if not incident_node:
        raise HTTPException(status_code=404, detail="Incident graph not found")
        
    edges = await attack_graph_edge_repository.get_edges_for_node(db, f"incident-{incident_id}")
    return {"nodes": [incident_node.node_data], "edges": [e.edge_data for e in edges]}

@router.get("/{incident_id}/attack-paths", response_model=List[AttackPath])
async def get_attack_paths(incident_id: str, db: AsyncSession = Depends(get_db)):
    assessment = await risk_assessment_repository.get_by_incident_id(db, incident_id)
    if assessment:
        return [AttackPath(**p) for p in assessment.assessment_data.get('attack_paths', [])]
    return []

@router.get("/{incident_id}/risk", response_model=RiskAssessment)
async def get_risk(incident_id: str, db: AsyncSession = Depends(get_db)):
    assessment = await risk_assessment_repository.get_by_incident_id(db, incident_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Risk assessment not found")
    return RiskAssessment(**assessment.assessment_data)

@router.post("/{incident_id}/risk/recalculate", response_model=RiskAssessment)
async def recalculate_risk(incident_id: str, db: AsyncSession = Depends(get_db)):
    incident_db = await incident_repository.get(db, incident_id)
    if not incident_db:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    # In a real app we'd convert DB model to Pydantic
    from app.schemas.incident import Incident
    incident = Incident(**incident_db.incident_data)
    
    # Mock fetching signals (needs signal_repository method by incident)
    signals_db = await signal_repository.get_multi(db) # This is mocked
    from app.schemas.signal import SecuritySignal
    signals = [SecuritySignal(**s.signal_data) for s in signals_db if str(s.signal_id) in incident.related_signal_ids]
    
    # Rebuild graph
    graph_builder = AttackGraphBuilder(db)
    # Events dict left empty for mocking in this endpoint
    await graph_builder.build_from_incident(incident, signals, {})
    
    # Recalculate risk
    risk_engine = RiskEngine(db)
    assessment = await risk_engine.calculate_risk(incident, signals)
    
    return assessment

@router.get("/{incident_id}/techniques", response_model=List[str])
async def get_techniques(incident_id: str, db: AsyncSession = Depends(get_db)):
    assessment = await risk_assessment_repository.get_by_incident_id(db, incident_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Risk assessment not found")
    return assessment.assessment_data.get('techniques', [])
