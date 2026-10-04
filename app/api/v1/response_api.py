from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from uuid import UUID
from typing import List, Dict, Any

from app.core.database import get_db
from app.schemas.response import ResponsePlan, ResponseAction
from app.services.response.engine import ResponseEngine

router = APIRouter(prefix="/api/v1", tags=["Response"])

@router.post("/incidents/{incident_id}/response-plan", response_model=ResponsePlan)
def generate_response_plan(incident_id: UUID, db: Session = Depends(get_db)):
    engine = ResponseEngine(db)
    plan = engine.generate_plan(incident_id)
    if not plan:
        raise HTTPException(status_code=404, detail="Incident not found or plan generation failed")
    return plan

@router.get("/incidents/{incident_id}/response-plan", response_model=ResponsePlan)
def get_response_plan(incident_id: UUID, db: Session = Depends(get_db)):
    engine = ResponseEngine(db)
    plan = engine.get_plan(incident_id)
    if not plan:
        raise HTTPException(status_code=404, detail="Response plan not found")
    return plan

@router.get("/incidents/{incident_id}/response-actions", response_model=List[ResponseAction])
def get_response_actions(incident_id: UUID, db: Session = Depends(get_db)):
    engine = ResponseEngine(db)
    return engine.get_actions(incident_id)

@router.get("/response-actions/{action_id}", response_model=ResponseAction)
def get_response_action(action_id: UUID, db: Session = Depends(get_db)):
    engine = ResponseEngine(db)
    action = engine.get_action(action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    return action

@router.post("/response-actions/{action_id}/approve")
def approve_action(action_id: UUID, db: Session = Depends(get_db)):
    engine = ResponseEngine(db)
    success = engine.approve_action(action_id, approver="ANALYST_1")
    if not success:
        raise HTTPException(status_code=400, detail="Approval failed")
    return {"status": "success", "message": "Action approved"}

@router.post("/response-actions/{action_id}/reject")
def reject_action(action_id: UUID, db: Session = Depends(get_db)):
    engine = ResponseEngine(db)
    success = engine.reject_action(action_id, approver="ANALYST_1")
    if not success:
        raise HTTPException(status_code=400, detail="Rejection failed")
    return {"status": "success", "message": "Action rejected"}

@router.post("/response-actions/{action_id}/cancel")
def cancel_action(action_id: UUID, db: Session = Depends(get_db)):
    engine = ResponseEngine(db)
    success = engine.cancel_action(action_id)
    if not success:
        raise HTTPException(status_code=400, detail="Cancellation failed")
    return {"status": "success", "message": "Action cancelled"}

@router.post("/response-actions/{action_id}/simulate")
def simulate_action(action_id: UUID, db: Session = Depends(get_db)):
    engine = ResponseEngine(db)
    result = engine.simulate_action(action_id)
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
