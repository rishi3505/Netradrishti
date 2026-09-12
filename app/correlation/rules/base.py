from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from app.schemas.signal import SecuritySignal
from app.schemas.incident import Incident
from app.schemas.correlation import CorrelationRuleSchema, CorrelationRuleConfig
from app.correlation.context import CorrelationContext
import uuid
from datetime import datetime

class CorrelationRule(ABC):
    """
    Base class for all correlation rules.
    """
    def __init__(self, config: Optional[CorrelationRuleConfig] = None):
        self.config = config or self.get_default_config()

    @classmethod
    @abstractmethod
    def get_metadata(cls) -> CorrelationRuleSchema:
        """Returns the metadata for this rule."""
        pass

    @classmethod
    @abstractmethod
    def get_default_config(cls) -> CorrelationRuleConfig:
        """Returns the default configuration for this rule."""
        pass

    @abstractmethod
    def is_applicable(self, new_signal: SecuritySignal) -> bool:
        """
        Quick check to determine if the rule should evaluate this new signal.
        """
        pass

    @abstractmethod
    async def analyze(self, new_signal: SecuritySignal, context: CorrelationContext) -> Optional[Incident]:
        """
        Analyzes the new signal in conjunction with historical context.
        Returns an Incident candidate if correlation conditions are met.
        """
        pass

    def create_incident(self, title: str, description: str, signals: List[SecuritySignal], 
                        affected_entities: set, mitre: List[str], reason: List[str]) -> Incident:
        """
        Helper to construct the Incident model.
        """
        from app.correlation.scoring import IncidentScorer
        from app.schemas.incident import IncidentStatus
        from app.schemas.common import MitreContext

        mitre_contexts = [MitreContext(technique_id=m) for m in mitre]
        
        confidence = IncidentScorer.calculate_confidence(signals, [self.get_metadata().rule_id])
        severity = self.config.severity_override or IncidentScorer.calculate_severity(signals)
        
        timeline = []
        for s in signals:
            timeline.append({
                "timestamp": s.created_at.isoformat(),
                "event": f"Signal Generated: {s.title}",
                "signal_id": str(s.signal_id)
            })
            
        evidence = {
            "correlation_rule": self.get_metadata().rule_id,
            "reasons": reason
        }

        # Collect related events from signals
        related_events = set()
        for s in signals:
            if s.related_event_ids:
                related_events.update(s.related_event_ids)

        return Incident(
            incident_id=uuid.uuid4(),
            title=title,
            description=description,
            status=IncidentStatus.NEW,
            severity=severity,
            confidence=confidence,
            related_signal_ids=[s.signal_id for s in signals],
            related_event_ids=list(related_events),
            affected_entities=list(affected_entities),
            mitre_techniques=mitre_contexts,
            timeline=timeline,
            evidence=evidence,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
