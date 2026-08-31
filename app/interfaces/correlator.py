from abc import ABC, abstractmethod
from app.schemas.signal import SecuritySignal
from app.schemas.incident import Incident
from typing import List, Optional, Any

class BaseCorrelator(ABC):

    @abstractmethod
    def find_related_events(self, signal: SecuritySignal) -> List[Any]:
        pass

    @abstractmethod
    def calculate_relationship(self, signals: List[SecuritySignal]) -> float:
        pass

    @abstractmethod
    def build_incident_candidate(self, signals: List[SecuritySignal]) -> Optional[Incident]:
        pass
