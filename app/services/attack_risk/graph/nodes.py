from app.schemas.attack_graph import AttackGraphNode, AttackGraphNodeType
from app.schemas.incident import Incident
from app.schemas.signal import SecuritySignal
from app.schemas.event import UnifiedSecurityEvent
from app.schemas.entity import Entity
from typing import Dict, Any

def create_incident_node(incident: Incident) -> AttackGraphNode:
    return AttackGraphNode(
        node_id=f"incident-{incident.incident_id}",
        node_type=AttackGraphNodeType.INCIDENT,
        source_reference=str(incident.incident_id),
        display_metadata={"title": incident.title, "severity": incident.severity.value if hasattr(incident.severity, "value") else incident.severity},
        timestamp=incident.created_at
    )

def create_signal_node(signal: SecuritySignal) -> AttackGraphNode:
    return AttackGraphNode(
        node_id=f"signal-{signal.signal_id}",
        node_type=AttackGraphNodeType.SIGNAL,
        source_reference=str(signal.signal_id),
        display_metadata={"type": signal.signal_type, "severity": signal.severity.value if hasattr(signal.severity, "value") else signal.severity},
        timestamp=signal.created_at
    )

def create_event_node(event: UnifiedSecurityEvent) -> AttackGraphNode:
    return AttackGraphNode(
        node_id=f"event-{event.event_identity.event_id}",
        node_type=AttackGraphNodeType.EVENT,
        source_reference=str(event.event_identity.event_id),
        display_metadata={"type": event.event_type},
        timestamp=event.timestamp
    )

def create_entity_node(entity: Entity) -> AttackGraphNode:
    return AttackGraphNode(
        node_id=f"entity-{entity.entity_id}",
        node_type=AttackGraphNodeType.ENTITY,
        source_reference=str(entity.entity_id),
        display_metadata={"entity_type": entity.entity_type.value if hasattr(entity.entity_type, "value") else entity.entity_type, "value": entity.value},
        timestamp=entity.last_seen
    )

def create_technique_node(technique_id: str, tactic: str) -> AttackGraphNode:
    return AttackGraphNode(
        node_id=f"technique-{technique_id}",
        node_type=AttackGraphNodeType.TECHNIQUE,
        source_reference=technique_id,
        display_metadata={"technique_id": technique_id, "tactic": tactic}
    )
