import string
from typing import Any, Optional
from .base import BaseNormalizer

class HashNormalizer(BaseNormalizer):
    def normalize(self, value: Any) -> Optional[str]:
        if not value:
            return None
            
        hash_val = str(value).strip().lower()
        
        # Check if valid hex
        if not all(c in string.hexdigits.lower() for c in hash_val):
            return None
            
        return hash_val

    def validate_length(self, hash_val: str, hash_type: str) -> bool:
        if not hash_val:
            return False
            
        lengths = {
            'md5': 32,
            'sha1': 40,
            'sha256': 64,
            'sha512': 128
        }
        
        expected_length = lengths.get(hash_type.lower())
        if expected_length and len(hash_val) != expected_length:
            return False
            
        return True
