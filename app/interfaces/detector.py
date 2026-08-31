from abc import ABC, abstractmethod
from app.schemas.event import UnifiedSecurityEvent
from app.schemas.signal import SecuritySignal
from typing import Optional

class BaseDetector(ABC):

    @abstractmethod
    def analyze(self, event: UnifiedSecurityEvent) -> bool:
        pass

    @abstractmethod
    def generate_signal(self, event: UnifiedSecurityEvent) -> Optional[SecuritySignal]:
        pass
