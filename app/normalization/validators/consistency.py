from typing import List
from app.schemas.event import UnifiedSecurityEvent
from app.normalization.normalizers.ip import IPNormalizer
from app.normalization.normalizers.hash import HashNormalizer

class ConsistencyValidator:
    def __init__(self):
        self.ip_norm = IPNormalizer()
        self.hash_norm = HashNormalizer()

    def validate(self, event: UnifiedSecurityEvent) -> List[str]:
        warnings = []
        
        # Validate Network IPs
        if event.network:
            if event.network.source_ip:
                if not self.ip_norm.normalize(event.network.source_ip):
                    warnings.append("Invalid network.source_ip")
            if event.network.destination_ip:
                if not self.ip_norm.normalize(event.network.destination_ip):
                    warnings.append("Invalid network.destination_ip")
                    
        # Validate File hashes
        if event.file:
            if event.file.md5 and not self.hash_norm.validate_length(event.file.md5, 'md5'):
                warnings.append("Invalid MD5 hash length")
            if event.file.sha1 and not self.hash_norm.validate_length(event.file.sha1, 'sha1'):
                warnings.append("Invalid SHA1 hash length")
            if event.file.sha256 and not self.hash_norm.validate_length(event.file.sha256, 'sha256'):
                warnings.append("Invalid SHA256 hash length")
                
        # Validate timestamp timezone awareness (datetime in Python should have tzinfo if aware)
        if event.identity.timestamp and event.identity.timestamp.tzinfo is None:
            warnings.append("Event timestamp is missing timezone information")
            
        return warnings
