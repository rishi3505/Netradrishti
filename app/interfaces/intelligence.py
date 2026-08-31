from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseIntelligence(ABC):

    @abstractmethod
    def lookup_ip(self, ip_address: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        pass
