from abc import ABC, abstractmethod
from typing import Dict, Any
from app.schemas.response import ResponseAction

class ResponseExecutionConnector(ABC):
    @abstractmethod
    def validate(self, action: ResponseAction) -> bool:
        """Validate if the action is supported and safe."""
        pass

    @abstractmethod
    def execute(self, action: ResponseAction) -> Dict[str, Any]:
        """Execute the action."""
        pass

    @abstractmethod
    def rollback(self, action: ResponseAction) -> Dict[str, Any]:
        """Rollback the action."""
        pass

    @abstractmethod
    def health_check(self) -> bool:
        """Check if connector is healthy and reachable."""
        pass
