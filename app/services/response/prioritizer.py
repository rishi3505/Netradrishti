from typing import List
from app.schemas.response import ResponseAction, ActionRisk, ActionCategory

class ActionPrioritizer:
    """Prioritizes response actions deterministically."""
    
    @staticmethod
    def prioritize(actions: List[ResponseAction]) -> List[ResponseAction]:
        for action in actions:
            action.priority = ActionPrioritizer._calculate_priority(action)
        
        # Sort P1 -> P4
        return sorted(actions, key=lambda a: a.priority)

    @staticmethod
    def _calculate_priority(action: ResponseAction) -> str:
        # P1 — Immediate investigation/containment consideration
        if action.category in [ActionCategory.CONTAINMENT] and action.risk == ActionRisk.HIGH:
            return "P1"
        
        # P2 — High priority
        if action.category in [ActionCategory.CONTAINMENT, ActionCategory.ERADICATION]:
            return "P2"
        if action.category == ActionCategory.INVESTIGATION and action.risk == ActionRisk.HIGH:
            return "P2"
            
        # P3 — Normal
        if action.category in [ActionCategory.INVESTIGATION, ActionCategory.EVIDENCE_COLLECTION, ActionCategory.MITIGATION, ActionCategory.RECOVERY]:
            return "P3"
            
        # P4 — Follow-up/prevention
        return "P4"
