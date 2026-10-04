from typing import Dict, Any
from app.schemas.response import ResponseAction, ActionStatus
from .base import ResponseExecutionConnector

class MockResponseConnector(ResponseExecutionConnector):
    """
    A deterministic mock executor.
    Never executes actual OS commands.
    """
    def validate(self, action: ResponseAction) -> bool:
        return True

    def execute(self, action: ResponseAction) -> Dict[str, Any]:
        return {
            "status": ActionStatus.SIMULATED,
            "action_id": str(action.action_id),
            "message": "No real system change was performed. Action simulated successfully."
        }

    def rollback(self, action: ResponseAction) -> Dict[str, Any]:
        return {
            "status": ActionStatus.SIMULATED,
            "action_id": str(action.action_id),
            "message": "No real system rollback was performed. Rollback simulated successfully."
        }

    def health_check(self) -> bool:
        return True
