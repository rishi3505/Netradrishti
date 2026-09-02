from abc import ABC, abstractmethod
from typing import Any, Dict
from app.schemas.event import UnifiedSecurityEvent

class BaseConnector(ABC):
    """
    Abstract base class for all data ingestion connectors.
    """
    
    @abstractmethod
    def validate_raw_event(self, raw_event: Dict[str, Any]) -> bool:
        """
        Validates whether the incoming raw event is structurally correct
        and belongs to this connector's source type.
        """
        pass

    @abstractmethod
    def transform(self, raw_event: Dict[str, Any]) -> UnifiedSecurityEvent:
        """
        Transforms the raw event into a standardized UnifiedSecurityEvent.
        """
        pass

    @abstractmethod
    def get_source_metadata(self) -> Dict[str, Any]:
        """
        Returns metadata about this connector.
        """
        pass

    @abstractmethod
    def health_check(self) -> bool:
        """
        Checks if the connector is healthy and ready to process events.
        """
        pass
