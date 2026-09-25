from abc import ABC, abstractmethod
from typing import Any, Dict
from app.schemas.ai_analysis import AIAnalysisResult

class AIAnalysisProvider(ABC):
    def __init__(self, config: Dict[str, Any]):
        self.config = config

    @abstractmethod
    async def analyze(self, context: Dict[str, Any], prompt: str) -> AIAnalysisResult:
        """
        Executes an analysis using the provider's logic.
        Must return a structured AIAnalysisResult.
        """
        pass

    @abstractmethod
    async def is_healthy(self) -> bool:
        """
        Returns true if the provider is currently reachable and authenticated.
        """
        pass
