from typing import Any, Optional, Dict, Tuple
from .base import BaseNormalizer

class UserNormalizer(BaseNormalizer):
    def normalize(self, value: Any) -> Optional[str]:
        if not value:
            return None
            
        username, domain = self.extract_components(value)
        return username

    def extract_components(self, value: Any) -> Tuple[Optional[str], Optional[str]]:
        """
        Extracts username and domain from strings like:
        - DOMAIN\username
        - username@domain.com
        - username
        """
        if not value:
            return None, None
            
        user_str = str(value).strip()
        
        # Windows style DOMAIN\username
        if '\\' in user_str:
            parts = user_str.split('\\', 1)
            return parts[1].lower(), parts[0].lower()
            
        # Email style username@domain
        if '@' in user_str:
            parts = user_str.rsplit('@', 1)
            return parts[0].lower(), parts[1].lower()
            
        return user_str.lower(), None
        
    def canonical_identity(self, value: Any) -> Optional[str]:
        username, domain = self.extract_components(value)
        if not username:
            return None
        if domain:
            return f"{domain}\\{username}"
        return username
