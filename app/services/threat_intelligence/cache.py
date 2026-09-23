import time
import threading
from typing import Optional, Dict
from app.schemas.threat_intel import ThreatIntelligenceResult

class TICache:
    def __init__(self, ttl_seconds: int = 3600):
        self.ttl_seconds = ttl_seconds
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()
        
    def _generate_key(self, indicator_type: str, normalized_indicator: str, provider: str) -> str:
        return f"{indicator_type}:{normalized_indicator}:{provider}"
        
    def get(self, indicator_type: str, normalized_indicator: str, provider: str) -> Optional[ThreatIntelligenceResult]:
        key = self._generate_key(indicator_type, normalized_indicator, provider)
        with self.lock:
            if key in self.cache:
                entry = self.cache[key]
                if time.time() - entry["timestamp"] < self.ttl_seconds:
                    return entry["result"]
                else:
                    del self.cache[key]
        return None
        
    def set(self, result: ThreatIntelligenceResult):
        key = self._generate_key(result.indicator_type.value, result.normalized_indicator, result.provider)
        with self.lock:
            self.cache[key] = {
                "timestamp": time.time(),
                "result": result
            }
            
    def clear(self):
        with self.lock:
            self.cache.clear()

# Global in-memory cache instance
ti_cache = TICache()
