from typing import Dict, Any, Tuple, List
from app.schemas.event import UnifiedSecurityEvent, EventLifecycle
from .normalizers.ip import IPNormalizer
from .normalizers.hostname import HostnameNormalizer
from .normalizers.domain import DomainNormalizer
from .normalizers.user import UserNormalizer
from .normalizers.hash import HashNormalizer
from .normalizers.url import URLNormalizer
from .validators.consistency import ConsistencyValidator

class NormalizationEngine:
    def __init__(self):
        self.ip_norm = IPNormalizer()
        self.host_norm = HostnameNormalizer()
        self.domain_norm = DomainNormalizer()
        self.user_norm = UserNormalizer()
        self.hash_norm = HashNormalizer()
        self.url_norm = URLNormalizer()
        self.validator = ConsistencyValidator()

    def normalize_event(self, event: UnifiedSecurityEvent) -> Tuple[UnifiedSecurityEvent, List[str]]:
        warnings = self.validator.validate(event)
        
        # Normalize Network
        if event.network:
            if event.network.source_ip:
                event.network.source_ip = self.ip_norm.normalize(event.network.source_ip) or event.network.source_ip
            if event.network.destination_ip:
                event.network.destination_ip = self.ip_norm.normalize(event.network.destination_ip) or event.network.destination_ip
                
        # Normalize Hosts
        if event.source_host:
            if event.source_host.hostname:
                normalized = self.host_norm.normalize(event.source_host.hostname)
                if normalized:
                    event.source_host.hostname = normalized
            if event.source_host.ip:
                event.source_host.ip = self.ip_norm.normalize(event.source_host.ip) or event.source_host.ip
                
        if event.destination_host:
            if event.destination_host.hostname:
                normalized = self.host_norm.normalize(event.destination_host.hostname)
                if normalized:
                    event.destination_host.hostname = normalized
            if event.destination_host.ip:
                event.destination_host.ip = self.ip_norm.normalize(event.destination_host.ip) or event.destination_host.ip

        # Normalize Users
        if event.user:
            if event.user.username:
                uname, domain = self.user_norm.extract_components(event.user.username)
                if uname:
                    event.user.username = uname
                if domain and not event.user.domain:
                    event.user.domain = domain
            if event.user.domain:
                event.user.domain = self.domain_norm.normalize(event.user.domain) or event.user.domain

        # Normalize Files
        if event.file:
            if event.file.md5:
                event.file.md5 = self.hash_norm.normalize(event.file.md5) or event.file.md5
            if event.file.sha1:
                event.file.sha1 = self.hash_norm.normalize(event.file.sha1) or event.file.sha1
            if event.file.sha256:
                event.file.sha256 = self.hash_norm.normalize(event.file.sha256) or event.file.sha256

        # Normalize Web
        if event.web:
            if event.web.domain:
                event.web.domain = self.domain_norm.normalize(event.web.domain) or event.web.domain
            if event.web.url:
                event.web.url = self.url_norm.normalize(event.web.url) or event.web.url

        event.lifecycle = EventLifecycle.NORMALIZED
        return event, warnings
