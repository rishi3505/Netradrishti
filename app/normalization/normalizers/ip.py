import ipaddress
from typing import Any, Optional, Dict
from .base import BaseNormalizer

class IPNormalizer(BaseNormalizer):
    def normalize(self, value: Any) -> Optional[str]:
        if not value:
            return None
        try:
            # Handle both string and IPvAnyAddress objects
            ip_str = str(value).strip()
            # Convert to canonical form
            return str(ipaddress.ip_address(ip_str))
        except ValueError:
            return None

    def classify(self, value: Any) -> Optional[str]:
        if not value:
            return None
        try:
            ip = ipaddress.ip_address(str(value).strip())
            return "private" if ip.is_private else "public"
        except ValueError:
            return None
