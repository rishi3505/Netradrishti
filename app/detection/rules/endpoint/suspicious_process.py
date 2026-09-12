from app.detection.rules.base import DetectionRule
from app.schemas.detection import DetectionRuleSchema, DetectionRuleConfig
from app.schemas.normalized_event import NormalizedEvent
from app.schemas.signal import SecuritySignal, DetectionMethod
from app.schemas.common import Severity
from app.detection.context import DetectionContext
from typing import Optional
import re

class SuspiciousProcessRule(DetectionRule):
    @classmethod
    def get_metadata(cls) -> DetectionRuleSchema:
        return DetectionRuleSchema(
            rule_id="END-001",
            rule_name="Suspicious Process Execution",
            description="Detects suspicious process command lines or parent-child relationships.",
            version="1.0",
            enabled=True,
            severity=Severity.HIGH,
            category="Endpoint",
            mitre_mapping=["T1059"],
            detection_type="rule_based",
            config=cls.get_default_config()
        )

    @classmethod
    def get_default_config(cls) -> DetectionRuleConfig:
        return DetectionRuleConfig(
            enabled=True,
            threshold=1,
            window_minutes=1,
            severity=Severity.HIGH,
            custom_params={
                "suspicious_commands": [
                    r"powershell.*-enc",
                    r"cmd\.exe.*/c.*echo",
                    r"vssadmin.*delete.*shadows",
                    r"bitsadmin.*transfer"
                ],
                "suspicious_parents": {
                    "cmd.exe": ["winword.exe", "excel.exe", "powerpnt.exe"],
                    "powershell.exe": ["winword.exe", "excel.exe"]
                }
            }
        )

    def is_applicable(self, event: NormalizedEvent) -> bool:
        cls = event.event.classification
        return (cls.event_category == "process" and 
                event.event.process is not None)

    async def analyze(self, event: NormalizedEvent, context: DetectionContext) -> Optional[SecuritySignal]:
        process_name = event.event.process.process_name
        parent_name = event.event.process.parent_process_name
        cmd_line = event.event.process.command_line
        
        suspicious_commands = self.config.custom_params.get("suspicious_commands", [])
        suspicious_parents = self.config.custom_params.get("suspicious_parents", {})
        
        is_suspicious = False
        reason = ""
        
        # Check command line regex
        if cmd_line:
            for pattern in suspicious_commands:
                if re.search(pattern, cmd_line, re.IGNORECASE):
                    is_suspicious = True
                    reason = f"Suspicious command line pattern matched: {pattern}"
                    break
                    
        # Check parent-child
        if not is_suspicious and process_name and parent_name:
            proc_lower = process_name.lower()
            parent_lower = parent_name.lower()
            
            if proc_lower in suspicious_parents:
                if parent_lower in suspicious_parents[proc_lower]:
                    is_suspicious = True
                    reason = f"Suspicious parent-child relationship: {parent_name} -> {process_name}"

        if is_suspicious:
            evidence = self.collect_evidence(
                process_name=process_name,
                parent_process_name=parent_name,
                command_line=cmd_line,
                reason=reason
            )
            
            return SecuritySignal(
                signal_type="Suspicious Process",
                detection_method=DetectionMethod.RULE_BASED,
                detection_rule_id="END-001",
                title=f"Suspicious Process Execution: {process_name}",
                description=reason,
                severity=self.config.severity,
                related_event_ids=[event.event.identity.event_id],
                affected_entities=[event.event.source_host.hostname] if event.event.source_host else [],
                evidence=evidence
            )
        return None
