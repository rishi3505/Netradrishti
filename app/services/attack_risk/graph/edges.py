from app.schemas.attack_graph import AttackGraphEdge, AttackGraphEdgeType
from typing import List

def create_edge(source_node_id: str, target_node_id: str, relationship: AttackGraphEdgeType, confidence: int = 100, evidence: List[str] = None, explanation: str = None) -> AttackGraphEdge:
    return AttackGraphEdge(
        source_node=source_node_id,
        destination_node=target_node_id,
        relationship_type=relationship,
        confidence=confidence,
        evidence_references=evidence or [],
        explanation=explanation
    )

def link_signal_to_incident(signal_node_id: str, incident_node_id: str) -> AttackGraphEdge:
    return create_edge(
        source_node_id=signal_node_id,
        target_node_id=incident_node_id,
        relationship=AttackGraphEdgeType.RELATED_TO,
        explanation="Signal is part of this Incident."
    )

def link_event_to_signal(event_node_id: str, signal_node_id: str) -> AttackGraphEdge:
    return create_edge(
        source_node_id=event_node_id,
        target_node_id=signal_node_id,
        relationship=AttackGraphEdgeType.SUPPORTS,
        explanation="Event triggered this Signal."
    )

def link_entity_to_event(entity_node_id: str, event_node_id: str) -> AttackGraphEdge:
    return create_edge(
        source_node_id=entity_node_id,
        target_node_id=event_node_id,
        relationship=AttackGraphEdgeType.ASSOCIATED_WITH,
        explanation="Entity observed in this Event."
    )

def link_technique_to_signal(technique_node_id: str, signal_node_id: str) -> AttackGraphEdge:
    return create_edge(
        source_node_id=signal_node_id,
        target_node_id=technique_node_id,
        relationship=AttackGraphEdgeType.USES_TECHNIQUE,
        explanation="Signal indicates use of this MITRE ATT&CK technique."
    )

def create_temporal_edge(node_a_id: str, node_b_id: str, time_diff_seconds: float) -> AttackGraphEdge:
    return create_edge(
        source_node_id=node_a_id,
        target_node_id=node_b_id,
        relationship=AttackGraphEdgeType.PRECEDED,
        explanation=f"Occurred {time_diff_seconds} seconds before."
    )
