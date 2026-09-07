from urllib.parse import urlparse, urlunparse
from typing import Any, Optional, Dict
from .base import BaseNormalizer
from .domain import DomainNormalizer

class URLNormalizer(BaseNormalizer):
    def __init__(self):
        self.domain_normalizer = DomainNormalizer()

    def normalize(self, value: Any) -> Optional[str]:
        if not value:
            return None
            
        url_str = str(value).strip()
        try:
            parsed = urlparse(url_str)
            # Normalize scheme
            scheme = parsed.scheme.lower()
            
            # Normalize domain
            netloc = parsed.netloc
            if netloc:
                # Handle port if present
                if ':' in netloc:
                    host, port = netloc.split(':', 1)
                    host = self.domain_normalizer.normalize(host) or host
                    netloc = f"{host}:{port}"
                else:
                    netloc = self.domain_normalizer.normalize(netloc) or netloc
                    
            # Reconstruct URL
            # We keep path, params, query, fragment mostly intact
            normalized = urlunparse((
                scheme,
                netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment
            ))
            return normalized
        except Exception:
            # If parsing fails, return original
            return url_str

    def extract_components(self, value: Any) -> Dict[str, str]:
        if not value:
            return {}
            
        try:
            parsed = urlparse(str(value).strip())
            return {
                "scheme": parsed.scheme.lower(),
                "domain": parsed.hostname.lower() if parsed.hostname else None,
                "path": parsed.path,
                "query": parsed.query
            }
        except Exception:
            return {}
