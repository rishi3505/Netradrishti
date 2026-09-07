from typing import Any, Optional, Dict
from .base import BaseNormalizer

class HostnameNormalizer(BaseNormalizer):
    def normalize(self, value: Any) -> Optional[str]:
        if not value:
            return None
        
        hostname = str(value).strip().lower()
        # Extract short hostname if FQDN
        if '.' in hostname:
            return hostname.split('.')[0]
        return hostname

    def extract_domain(self, value: Any) -> Optional[str]:
        """Extracts the domain part if the hostname is an FQDN"""
        if not value:
            return None
            
        hostname = str(value).strip().lower()
        parts = hostname.split('.', 1)
        if len(parts) > 1:
            return parts[1]
        return None
