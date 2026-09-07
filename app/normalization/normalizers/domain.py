from typing import Any, Optional
from .base import BaseNormalizer

class DomainNormalizer(BaseNormalizer):
    def normalize(self, value: Any) -> Optional[str]:
        if not value:
            return None
            
        domain = str(value).strip().lower()
        # Remove trailing dot if present
        if domain.endswith('.'):
            domain = domain[:-1]
            
        # Basic validation for reasonable domain structure
        if '.' not in domain or len(domain) < 3:
            # We don't reject it completely, but return as is, it might be a local domain
            pass
            
        return domain
