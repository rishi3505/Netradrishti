from typing import List, Dict, Any
from app.schemas.incident import Incident
from app.schemas.response import ResponseAction, ActionCategory, ActionRisk, Reversibility
from .base import ResponsePlaybook

class NetworkAttackPlaybook(ResponsePlaybook):
    def matches(self, incident: Incident, context: Dict[str, Any]) -> bool:
        title = incident.title.lower()
        if "network" in title or "scanning" in title or "outbound" in title:
            return True
        for mitre in incident.mitre_techniques:
            if mitre.tactic.lower() in ["discovery", "command and control", "exfiltration"]:
                return True
        return False

    def generate_actions(self, incident: Incident, context: Dict[str, Any]) -> List[ResponseAction]:
        actions = []
        actions.append(ResponseAction(
            incident_id=incident.incident_id,
            action_type="investigate_outbound_connections",
            category=ActionCategory.INVESTIGATION,
            description="Investigate suspicious outbound connections.",
            rationale="Determine the destination, volume of data, and associated process.",
            expected_effect="Clear understanding of network communication.",
            risk=ActionRisk.LOW,
            approval_required=False,
            reversibility=Reversibility.REVERSIBLE
        ))
        
        actions.append(ResponseAction(
            incident_id=incident.incident_id,
            action_type="block_ip",
            category=ActionCategory.CONTAINMENT,
            description="Block malicious network destination.",
            rationale="Stop communication with C2 or exfiltration endpoints.",
            expected_effect="Traffic to destination IP/domain is dropped at firewall.",
            risk=ActionRisk.MEDIUM,
            approval_required=True,
            reversibility=Reversibility.REVERSIBLE,
            rollback_considerations="Remove temporary block after investigation and validation."
        ))

        actions.append(ResponseAction(
            incident_id=incident.incident_id,
            action_type="network_segmentation",
            category=ActionCategory.PREVENTION,
            description="Improve network segmentation.",
            rationale="Limit lateral movement and unauthorized outbound access.",
            expected_effect="Reduced attack surface.",
            risk=ActionRisk.LOW,
            approval_required=False,
            reversibility=Reversibility.REVERSIBLE
        ))
        return actions
