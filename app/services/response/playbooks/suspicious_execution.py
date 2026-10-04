from typing import List, Dict, Any
from app.schemas.incident import Incident
from app.schemas.response import ResponseAction, ActionCategory, ActionRisk, Reversibility
from .base import ResponsePlaybook

class SuspiciousExecutionPlaybook(ResponsePlaybook):
    
    def matches(self, incident: Incident, context: Dict[str, Any]) -> bool:
        title_lower = incident.title.lower()
        if "suspicious" in title_lower and ("process" in title_lower or "execution" in title_lower or "powershell" in title_lower):
            return True
        for mitre in incident.mitre_techniques:
            if mitre.tactic.lower() == "execution":
                return True
        return False

    def generate_actions(self, incident: Incident, context: Dict[str, Any]) -> List[ResponseAction]:
        actions = []
        
        actions.append(ResponseAction(
            incident_id=incident.incident_id,
            action_type="inspect_process_tree",
            category=ActionCategory.INVESTIGATION,
            description="Inspect the process tree for the suspicious execution.",
            rationale="Identify parent process and any spawned child processes to understand the scope.",
            expected_effect="Better understanding of the execution chain.",
            risk=ActionRisk.LOW,
            approval_required=False,
            reversibility=Reversibility.REVERSIBLE
        ))

        actions.append(ResponseAction(
            incident_id=incident.incident_id,
            action_type="isolate_host",
            category=ActionCategory.CONTAINMENT,
            description="Consider isolating the affected workstation.",
            rationale="Prevent potential lateral movement or data exfiltration from the suspicious process.",
            expected_effect="Host will lose normal network connectivity but remain accessible to security tools.",
            risk=ActionRisk.HIGH,
            approval_required=True,
            reversibility=Reversibility.REVERSIBLE,
            rollback_considerations="Restore network connectivity after containment criteria are satisfied."
        ))

        actions.append(ResponseAction(
            incident_id=incident.incident_id,
            action_type="terminate_process",
            category=ActionCategory.ERADICATION,
            description="Terminate the suspicious process.",
            rationale="Stop the malicious activity immediately.",
            expected_effect="Suspicious process and children stopped.",
            risk=ActionRisk.MEDIUM,
            approval_required=True,
            reversibility=Reversibility.PARTIALLY_REVERSIBLE
        ))

        actions.append(ResponseAction(
            incident_id=incident.incident_id,
            action_type="improve_logging",
            category=ActionCategory.PREVENTION,
            description="Improve PowerShell and process execution logging.",
            rationale="Enhance visibility for future execution anomalies.",
            expected_effect="More detailed telemetry available for future detection.",
            risk=ActionRisk.LOW,
            approval_required=False,
            reversibility=Reversibility.REVERSIBLE
        ))

        return actions
