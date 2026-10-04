from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID
from typing import List, Dict, Any

from app.api.dependencies import get_db
from app.schemas.response import ResponsePlan, ResponseAction
from app.services.response.engine import ResponseEngine

router = APIRouter(prefix="/api/v1", tags=["Response"])

@router.post("/incidents/{incident_id}/response-plan", response_model=ResponsePlan)
async def generate_response_plan(incident_id: UUID, db: AsyncSession = Depends(get_db)):
    engine = ResponseEngine(db)
    plan = await engine.generate_plan(incident_id)
    if not plan:
        raise HTTPException(status_code=404, detail="Incident not found or plan generation failed")
    return plan

@router.get("/incidents/{incident_id}/response-plan", response_model=ResponsePlan)
async def get_response_plan(incident_id: UUID, db: AsyncSession = Depends(get_db)):
    engine = ResponseEngine(db)
    plan = await engine.get_plan(incident_id)
    if not plan:
        raise HTTPException(status_code=404, detail="Response plan not found")
    return plan

@router.get("/incidents/{incident_id}/response-actions", response_model=List[ResponseAction])
async def get_response_actions(incident_id: UUID, db: AsyncSession = Depends(get_db)):
    engine = ResponseEngine(db)
    return await engine.get_actions(incident_id)

@router.get("/response-actions/{action_id}", response_model=ResponseAction)
async def get_response_action(action_id: UUID, db: AsyncSession = Depends(get_db)):
    engine = ResponseEngine(db)
    action = await engine.get_action(action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    return action

@router.post("/response-actions/{action_id}/approve")
async def approve_action(action_id: UUID, db: AsyncSession = Depends(get_db)):
    engine = ResponseEngine(db)
    await engine.approve_action(action_id, approver="ANALYST_1")
    return {"status": "success", "message": "Action approved"}

@router.post("/response-actions/{action_id}/reject")
async def reject_action(action_id: UUID, db: AsyncSession = Depends(get_db)):
    engine = ResponseEngine(db)
    await engine.reject_action(action_id, approver="ANALYST_1")
    return {"status": "success", "message": "Action rejected"}

@router.post("/response-actions/{action_id}/cancel")
async def cancel_action(action_id: UUID, db: AsyncSession = Depends(get_db)):
    engine = ResponseEngine(db)
    await engine.cancel_action(action_id)
    return {"status": "success", "message": "Action cancelled"}

@router.post("/response-actions/{action_id}/simulate")
async def simulate_action(action_id: UUID, db: AsyncSession = Depends(get_db)):
    engine = ResponseEngine(db)
    result = await engine.simulate_action(action_id)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

@router.get("/response/playbooks")
def list_playbooks():
    from app.services.response.registry import response_registry
    return {"playbooks": [type(pb).__name__ for pb in response_registry._playbooks]}

@router.get("/response/connectors")
def list_connectors():
    from app.services.response.registry import response_registry
    return {"connectors": list(response_registry._connectors.keys())}
