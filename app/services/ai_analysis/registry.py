from typing import Dict, Type, Any
from app.services.ai_analysis.providers.base import AIAnalysisProvider
from app.services.ai_analysis.providers.mock import MockAIProvider

class AIProviderRegistry:
    def __init__(self):
        self._providers: Dict[str, Type[AIAnalysisProvider]] = {
            "mock": MockAIProvider
        }

    def register(self, name: str, provider_class: Type[AIAnalysisProvider]):
        self._providers[name] = provider_class

    def get_provider(self, name: str, config: Dict[str, Any]) -> AIAnalysisProvider:
        provider_class = self._providers.get(name)
        if not provider_class:
            raise ValueError(f"AI Provider '{name}' is not registered.")
        return provider_class(config)

ai_provider_registry = AIProviderRegistry()
