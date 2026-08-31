from abc import ABC, abstractmethod
from typing import Any, Dict
from app.schemas.event import UnifiedSecurityEvent

class BaseConnector(ABC):
    
    @abstractmethod
    def fetch(self) -> Any:
        pass

    @abstractmethod
    def validate(self, raw_event: Any) -> bool:
        pass

    @abstractmethod
    def transform(self, raw_event: Any) -> UnifiedSecurityEvent:
        pass
