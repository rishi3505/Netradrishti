from uuid import UUID
from typing import Dict, Any, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime

from app.schemas.incident import Incident
from app.schemas.response import ResponsePlan, ResponseAction, ActionStatus
from app.models.database_models import DBResponsePlan, DBResponseAction, DBIncident
from app.services.response.planner import ResponsePlanner
from app.services.response.registry import response_registry


class ResponseEngine:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.planner = ResponsePlanner()

    async def generate_plan(self, incident_id: UUID) -> Optional[ResponsePlan]:
        result = await self.db.execute(
            select(DBIncident).filter(DBIncident.incident_id == incident_id)
        )
        db_incident = result.scalar_one_or_none()
        if not db_incident:
            return None

        incident = Incident(**db_incident.incident_data)

        context = {
            "risk_assessment": None,
            "attack_path": None,
            "ai_analysis": None
        }

        plan = self.planner.generate_plan(incident, context)
        await self._save_plan(plan)
        return plan

    async def _save_plan(self, plan: ResponsePlan):
        db_plan = DBResponsePlan(
            plan_id=plan.plan_id,
            incident_id=str(plan.incident_id),
            status=plan.status,
            priority=plan.priority,
            approval_required=str(plan.approval_required),
            plan_data=plan.dict()
        )
        self.db.add(db_plan)

        for action in plan.actions:
            action.plan_id = plan.plan_id
            db_action = DBResponseAction(
                action_id=action.action_id,
                plan_id=plan.plan_id,
                incident_id=str(plan.incident_id),
                action_type=action.action_type,
                category=action.category,
                status=action.status,
                priority=action.priority,
                risk=action.risk,
                approval_required=str(action.approval_required),
                action_data=action.dict()
            )
            self.db.add(db_action)

        await self.db.commit()

    async def get_plan(self, incident_id: UUID) -> Optional[ResponsePlan]:
        result = await self.db.execute(
            select(DBResponsePlan).filter(DBResponsePlan.incident_id == str(incident_id))
        )
        db_plan = result.scalar_one_or_none()
        if not db_plan:
            return None
        return ResponsePlan(**db_plan.plan_data)

    async def get_actions(self, incident_id: UUID) -> List[ResponseAction]:
        result = await self.db.execute(
            select(DBResponseAction).filter(DBResponseAction.incident_id == str(incident_id))
        )
        db_actions = result.scalars().all()
        return [ResponseAction(**a.action_data) for a in db_actions]

    async def get_action(self, action_id: UUID) -> Optional[ResponseAction]:
        result = await self.db.execute(
            select(DBResponseAction).filter(DBResponseAction.action_id == action_id)
        )
        db_action = result.scalar_one_or_none()
        if not db_action:
            return None
        return ResponseAction(**db_action.action_data)

    async def _update_action_status(
        self, action_id: UUID, status: ActionStatus,
        approver: str = None, reason: str = None
    ):
        result = await self.db.execute(
            select(DBResponseAction).filter(DBResponseAction.action_id == action_id)
        )
        db_action = result.scalar_one_or_none()
        if db_action:
            db_action.status = status
            action_data = db_action.action_data.copy()
            action_data["status"] = status
            if approver:
                action_data["approver_id"] = approver
                action_data["approval_timestamp"] = datetime.utcnow().isoformat()
            if reason:
                action_data["approval_reason"] = reason
            db_action.action_data = action_data
            await self.db.commit()

    async def approve_action(self, action_id: UUID, approver: str, reason: str = None) -> bool:
        await self._update_action_status(action_id, ActionStatus.APPROVED, approver, reason)
        return True

    async def reject_action(self, action_id: UUID, approver: str, reason: str = None) -> bool:
        await self._update_action_status(action_id, ActionStatus.REJECTED, approver, reason)
        return True

    async def cancel_action(self, action_id: UUID) -> bool:
        await self._update_action_status(action_id, ActionStatus.CANCELLED)
        return True

    async def simulate_action(self, action_id: UUID) -> Dict[str, Any]:
        action = await self.get_action(action_id)
        if not action:
            return {"error": "Action not found"}

        if action.approval_required and action.status != ActionStatus.APPROVED:
            return {"error": "Action requires approval before execution."}

        connector = response_registry.get_connector("mock")
        if not connector:
            return {"error": "Mock connector not found"}

        result = connector.execute(action)
        await self._update_action_status(action_id, ActionStatus.SIMULATED)
        return result
