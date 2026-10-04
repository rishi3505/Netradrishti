from typing import List, Dict, Any
from app.schemas.incident import Incident
from app.schemas.response import ResponseAction, ActionCategory, ActionRisk, Reversibility
from .base import ResponsePlaybook

class CredentialAttackPlaybook(ResponsePlaybook):
    
    def matches(self, incident: Incident, context: Dict[str, Any]) -> bool:
        # Match if title or techniques suggest credential attack
        title_lower = incident.title.lower()
        if "brute force" in title_lower or "password attack" in title_lower or "authentication" in title_lower:
            return True
        for mitre in incident.mitre_techniques:
            if mitre.tactic.lower() == "credential access":
                return True
        return False

    def generate_actions(self, incident: Incident, context: Dict[str, Any]) -> List[ResponseAction]:
        actions = []
        
        # Investigation
        actions.append(ResponseAction(
            incident_id=incident.incident_id,
            action_type="investigate_auth_logs",
            category=ActionCategory.INVESTIGATION,
            description="Review authentication logs for the affected accounts.",
            rationale="Need to determine if any authentication attempts were successful and identify source IPs.",
            expected_effect="Identify compromised accounts and attacker infrastructure.",
            risk=ActionRisk.LOW,
            approval_required=False,
            reversibility=Reversibility.REVERSIBLE
        ))

        # Containment
        actions.append(ResponseAction(
            incident_id=incident.incident_id,
            action_type="disable_account",
            category=ActionCategory.CONTAINMENT,
            description="Disable compromised accounts temporarily.",
            rationale="Stop ongoing unauthorized access using these credentials.",
            expected_effect="Attacker will lose access via these accounts.",
            risk=ActionRisk.MEDIUM,
            approval_required=True,
            reversibility=Reversibility.REVERSIBLE,
            rollback_considerations="Re-enable account after password reset and MFA verification."
        ))

        # Mitigation
        actions.append(ResponseAction(
            incident_id=incident.incident_id,
            action_type="reset_credentials",
            category=ActionCategory.MITIGATION,
            description="Force password reset for affected accounts.",
            rationale="Invalidate the compromised credentials.",
            expected_effect="Accounts secured with new credentials.",
            risk=ActionRisk.MEDIUM,
            approval_required=True,
            reversibility=Reversibility.PARTIALLY_REVERSIBLE
        ))

        # Prevention
        actions.append(ResponseAction(
            incident_id=incident.incident_id,
            action_type="enable_mcp",
            category=ActionCategory.PREVENTION,
            description="Enable MFA for affected accounts.",
            rationale="Prevent future password-only compromises.",
            expected_effect="Improved authentication security.",
            risk=ActionRisk.LOW,
            approval_required=False,
            reversibility=Reversibility.REVERSIBLE
        ))

        return actions
