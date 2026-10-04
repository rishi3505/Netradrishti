from typing import List, Optional
from app.schemas.response import ResponseAction, ActionRisk, ActionCategory
from app.schemas.incident import Incident

class ActionValidator:
    """Validates AI recommendations against supported safe actions and constraints."""
    
    SUPPORTED_ACTION_TYPES = {
        "investigate_auth_logs",
        "disable_account",
        "reset_credentials",
        "enable_mcp",
        "inspect_process_tree",
        "isolate_host",
        "terminate_process",
        "improve_logging",
        "preserve_files",
        "remove_malware",
        "improve_endpoint_protection",
        "investigate_outbound_connections",
        "block_ip",
        "network_segmentation",
        "investigate_cross_environment",
        "isolate_multiple_hosts",
        "validate_system_integrity",
        "ai_advisory_investigation", # AI generic allowed action
        "ai_advisory_containment"
    }

    HIGH_IMPACT_ACTIONS = {
        "isolate_host",
        "isolate_multiple_hosts",
        "disable_account",
        "reset_credentials",
        "block_ip",
        "terminate_process",
        "remove_malware"
    }

    @staticmethod
    def validate_action(action: ResponseAction, incident: Incident) -> bool:
        """Return True if the action is safe and valid."""
        
        if action.action_type not in ActionValidator.SUPPORTED_ACTION_TYPES:
            return False
            
        if action.action_type in ActionValidator.HIGH_IMPACT_ACTIONS:
            # Must require approval
            if not action.approval_required:
                action.approval_required = True
            
            # Risk should generally reflect the high impact
            if action.risk == ActionRisk.LOW:
                action.risk = ActionRisk.HIGH
                
        return True
