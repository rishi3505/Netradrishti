from typing import List
from app.schemas.event import UnifiedSecurityEvent
from app.schemas.entity import ExtractedEntity, EntityType

class EntityExtractor:
    def extract(self, event: UnifiedSecurityEvent) -> List[ExtractedEntity]:
        entities = []
        event_id = event.identity.event_id
        
        # Extract IP and Host from Network/HostInfo
        if event.network:
            if event.network.source_ip:
                entities.append(ExtractedEntity(
                    entity_type=EntityType.IP,
                    value=str(event.network.source_ip),
                    normalized_value=str(event.network.source_ip),
                    source_event_id=event_id
                ))
            if event.network.destination_ip:
                entities.append(ExtractedEntity(
                    entity_type=EntityType.IP,
                    value=str(event.network.destination_ip),
                    normalized_value=str(event.network.destination_ip),
                    source_event_id=event_id
                ))
                
        if event.source_host:
            if event.source_host.hostname:
                entities.append(ExtractedEntity(
                    entity_type=EntityType.HOST,
                    value=event.source_host.hostname,
                    normalized_value=event.source_host.hostname.lower(),
                    source_event_id=event_id,
                    attributes={
                        "ip": str(event.source_host.ip) if event.source_host.ip else None,
                        "device_id": event.source_host.device_id,
                        "mac_address": event.source_host.mac_address
                    }
                ))
                
        if event.destination_host:
            if event.destination_host.hostname:
                entities.append(ExtractedEntity(
                    entity_type=EntityType.HOST,
                    value=event.destination_host.hostname,
                    normalized_value=event.destination_host.hostname.lower(),
                    source_event_id=event_id,
                    attributes={
                        "ip": str(event.destination_host.ip) if event.destination_host.ip else None,
                        "device_id": event.destination_host.device_id,
                        "mac_address": event.destination_host.mac_address
                    }
                ))
                
        if event.user:
            if event.user.username:
                val = f"{event.user.domain}\\{event.user.username}" if event.user.domain else event.user.username
                entities.append(ExtractedEntity(
                    entity_type=EntityType.USER,
                    value=val,
                    normalized_value=val.lower(),
                    source_event_id=event_id,
                    attributes={
                        "domain": event.user.domain,
                        "email": event.user.email
                    }
                ))
                
        if event.file:
            # For files, the value could be the hash or path. Let's use the hash as primary if available
            hash_val = event.file.sha256 or event.file.md5 or event.file.sha1
            if hash_val:
                entities.append(ExtractedEntity(
                    entity_type=EntityType.FILE,
                    value=hash_val,
                    normalized_value=hash_val.lower(),
                    source_event_id=event_id,
                    attributes={
                        "file_name": event.file.file_name,
                        "file_path": event.file.file_path
                    }
                ))

        if event.process:
            if event.process.process_name:
                entities.append(ExtractedEntity(
                    entity_type=EntityType.PROCESS,
                    value=event.process.process_name,
                    normalized_value=event.process.process_name.lower(),
                    source_event_id=event_id,
                    attributes={
                        "command_line": event.process.command_line,
                        "process_hash": event.process.process_hash
                    }
                ))
                
        if event.web:
            if event.web.domain:
                entities.append(ExtractedEntity(
                    entity_type=EntityType.DOMAIN,
                    value=event.web.domain,
                    normalized_value=event.web.domain.lower(),
                    source_event_id=event_id
                ))
                
        return entities
