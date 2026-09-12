from abc import ABC, abstractmethod
from typing import Optional, Any, Dict, List
from app.schemas.normalized_event import NormalizedEvent
from app.schemas.signal import SecuritySignal
from app.schemas.detection import DetectionRuleSchema, DetectionRuleConfig
from app.detection.context import DetectionContext

class DetectionRule(ABC):
    """
    Base class for all detection rules.
    """
    def __init__(self, config: Optional[DetectionRuleConfig] = None):
        self.config = config or self.get_default_config()

    @classmethod
    @abstractmethod
    def get_metadata(cls) -> DetectionRuleSchema:
        """Returns the metadata for this rule."""
        pass

    @classmethod
    @abstractmethod
    def get_default_config(cls) -> DetectionRuleConfig:
        """Returns the default configuration for this rule."""
        pass

    @abstractmethod
    def is_applicable(self, event: NormalizedEvent) -> bool:
        """
        Quick check to determine if the rule should process this event.
        Returns True if the event matches the rule's criteria.
        """
        pass

    @abstractmethod
    async def analyze(self, event: NormalizedEvent, context: DetectionContext) -> Optional[SecuritySignal]:
        """
        Analyzes the event within the given context.
        Returns a SecuritySignal if suspicious activity is detected, else None.
        """
        pass

    def collect_evidence(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Helper to collect and format evidence consistently.
        """
        return kwargs
