from abc import ABC, abstractmethod
from typing import List, Dict, Any
from app.schemas.incident import Incident
from app.schemas.response import ResponseAction

class ResponsePlaybook(ABC):
    
    @abstractmethod
    def matches(self, incident: Incident, context: Dict[str, Any]) -> bool:
        """Return True if this playbook applies to the incident."""
        pass

    @abstractmethod
    def generate_actions(self, incident: Incident, context: Dict[str, Any]) -> List[ResponseAction]:
        """Generate response actions for this incident."""
        pass
