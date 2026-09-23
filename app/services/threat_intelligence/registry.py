from typing import Dict, Optional, List
from app.services.threat_intelligence.providers.base import ThreatIntelligenceProvider
from app.services.threat_intelligence.providers.mock import MockProvider
from app.core.config import settings

class ThreatIntelligenceRegistry:
    def __init__(self):
        self._providers: Dict[str, ThreatIntelligenceProvider] = {}
        self._register_default_providers()
        
    def _register_default_providers(self):
        # Register mock provider
        mock = MockProvider()
        self._providers[mock.name] = mock
        
        # Future providers (VirusTotal, etc.) can be registered here based on config
        
    def register(self, provider: ThreatIntelligenceProvider):
        self._providers[provider.name] = provider
        
    def get_provider(self, name: str) -> Optional[ThreatIntelligenceProvider]:
        return self._providers.get(name)
        
    def get_all_providers(self) -> List[ThreatIntelligenceProvider]:
        return list(self._providers.values())
        
    def get_enabled_providers(self) -> List[ThreatIntelligenceProvider]:
        # For now, if settings.THREAT_INTEL_PROVIDER is 'all', return all. Otherwise, return the selected one.
        if settings.THREAT_INTEL_PROVIDER == "all":
            return self.get_all_providers()
        else:
            provider = self.get_provider(settings.THREAT_INTEL_PROVIDER)
            return [provider] if provider else []

registry = ThreatIntelligenceRegistry()
