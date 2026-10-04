from typing import List, Dict, Any
from app.schemas.incident import Incident
from app.schemas.response import ResponseAction, ActionCategory, ActionRisk, Reversibility
from .base import ResponsePlaybook

class MultiSourceCompromisePlaybook(ResponsePlaybook):
    def matches(self, incident: Incident, context: Dict[str, Any]) -> bool:
        # Match if the incident has multiple sources or complex attack paths
        if getattr(incident, "risk_score", 0) and incident.risk_score > 80:
            return True
        if incident.title and "multi-source" in incident.title.lower():
            return True
        return False

    def generate_actions(self, incident: Incident, context: Dict[str, Any]) -> List[ResponseAction]:
        actions = []
        actions.append(ResponseAction(
            incident_id=incident.incident_id,
            action_type="investigate_cross_environment",
            category=ActionCategory.INVESTIGATION,
            description="Search for the same IOCs across the entire environment.",
            rationale="Identify the full scope of a multi-source compromise.",
            expected_effect="Complete visibility into affected assets.",
            risk=ActionRisk.LOW,
            approval_required=False,
            reversibility=Reversibility.REVERSIBLE
        ))

        actions.append(ResponseAction(
            incident_id=incident.incident_id,
            action_type="isolate_multiple_hosts",
            category=ActionCategory.CONTAINMENT,
            description="Isolate all affected endpoints identified in the attack graph.",
            rationale="Halt widespread lateral movement immediately.",
            expected_effect="Multiple hosts lose network connectivity.",
            risk=ActionRisk.HIGH,
            approval_required=True,
            reversibility=Reversibility.REVERSIBLE
        ))
        
        actions.append(ResponseAction(
            incident_id=incident.incident_id,
            action_type="validate_system_integrity",
            category=ActionCategory.RECOVERY,
            description="Validate system integrity across all restored hosts.",
            rationale="Ensure no persistence mechanisms remain before restoring network access.",
            expected_effect="Confirmed clean state for affected assets.",
            risk=ActionRisk.LOW,
            approval_required=False,
            reversibility=Reversibility.REVERSIBLE
        ))

        return actions
