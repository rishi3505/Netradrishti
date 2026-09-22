from typing import Optional, Tuple, Dict, Any
import ipaddress
import re
from urllib.parse import urlparse
from app.schemas.threat_intel import IndicatorType

def identify_and_normalize(indicator: str) -> Tuple[Optional[IndicatorType], str]:
    indicator = indicator.strip()
    if not indicator:
        return None, indicator
        
    # Check IP
    try:
        ip = ipaddress.ip_address(indicator)
        if ip.version == 4:
            return IndicatorType.IPV4, str(ip)
        elif ip.version == 6:
            return IndicatorType.IPV6, str(ip)
    except ValueError:
        pass
        
    # Check Hash (MD5, SHA1, SHA256)
    if re.match(r"^[a-fA-F0-9]{32}$", indicator):
        return IndicatorType.MD5, indicator.lower()
    if re.match(r"^[a-fA-F0-9]{40}$", indicator):
        return IndicatorType.SHA1, indicator.lower()
    if re.match(r"^[a-fA-F0-9]{64}$", indicator):
        return IndicatorType.SHA256, indicator.lower()
        
    # Check URL
    if indicator.startswith("http://") or indicator.startswith("https://") or indicator.startswith("ftp://"):
        try:
            parsed = urlparse(indicator)
            if parsed.hostname:
                return IndicatorType.URL, indicator
        except Exception:
            pass
            
    # Check Domain
    if re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", indicator):
        return IndicatorType.DOMAIN, indicator.lower()
        
    return None, indicator

def normalize_indicator(indicator: str, expected_type: IndicatorType) -> str:
    _, normalized = identify_and_normalize(indicator)
    return normalized
