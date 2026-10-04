from typing import List, Dict, Any
from app.schemas.incident import Incident
from app.schemas.response import ResponsePlan, ResponseAction
from .registry import response_registry
from .prioritizer import ActionPrioritizer
from .validation import ActionValidator

class ResponsePlanner:
    def __init__(self):
        self.prioritizer = ActionPrioritizer()
        self.validator = ActionValidator()

    def generate_plan(self, incident: Incident, context: Dict[str, Any]) -> ResponsePlan:
        playbooks = response_registry.get_matching_playbooks(incident, context)
        
        actions: List[ResponseAction] = []
        for playbook in playbooks:
            pb_actions = playbook.generate_actions(incident, context)
            actions.extend(pb_actions)

        # Deduplicate actions
        unique_actions = []
        seen = set()
        for a in actions:
            key = f"{a.action_type}:{a.incident_id}"
            if key not in seen:
                seen.add(key)
                unique_actions.append(a)

        # Validate
        valid_actions = []
        for a in unique_actions:
            if self.validator.validate_action(a, incident):
                valid_actions.append(a)

        # Prioritize
        prioritized_actions = self.prioritizer.prioritize(valid_actions)
        
        # Calculate plan overall approval requirement
        plan_approval_required = any(a.approval_required for a in prioritized_actions)

        plan = ResponsePlan(
            incident_id=incident.incident_id,
            actions=prioritized_actions,
            approval_required=plan_approval_required
        )
        return plan
