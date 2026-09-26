from typing import List, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from app.schemas.incident import Incident
from app.schemas.signal import SecuritySignal
from app.schemas.event import UnifiedSecurityEvent
from app.schemas.attack_graph import AttackGraphNode, AttackGraphEdge
from app.services.attack_risk.graph.nodes import (
    create_incident_node, create_signal_node, create_event_node, create_technique_node
)
from app.services.attack_risk.graph.edges import (
    link_signal_to_incident, link_event_to_signal, link_technique_to_signal, create_temporal_edge
)
from app.repositories.attack_graph_repository import attack_graph_node_repository, attack_graph_edge_repository

class AttackGraphBuilder:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.nodes: dict[str, AttackGraphNode] = {}
        self.edges: list[AttackGraphEdge] = []

    def _add_node(self, node: AttackGraphNode):
        self.nodes[node.node_id] = node

    def _add_edge(self, edge: AttackGraphEdge):
        self.edges.append(edge)

    async def build_from_incident(self, incident: Incident, signals: List[SecuritySignal], events_by_signal: dict[str, List[UnifiedSecurityEvent]]):
        # 1. Incident Node
        incident_node = create_incident_node(incident)
        self._add_node(incident_node)
        
        # We will sort signals chronologically to build temporal edges
        sorted_signals = sorted([s for s in signals if s.created_at], key=lambda x: x.created_at)

        prev_signal_node_id = None
        
        # 2. Signal Nodes & Edges
        for signal in sorted_signals:
            sig_node = create_signal_node(signal)
            self._add_node(sig_node)
            self._add_edge(link_signal_to_incident(sig_node.node_id, incident_node.node_id))
            
            # Temporal logic
            if prev_signal_node_id and signal.created_at:
                # Add preceded edge
                # Time diff calculation might require the previous signal object, assuming simple sequence for now
                self._add_edge(create_temporal_edge(prev_signal_node_id, sig_node.node_id, 0)) # time_diff abstracted
            prev_signal_node_id = sig_node.node_id
            
            # 3. MITRE Techniques
            if hasattr(signal, 'mitre_mapping') and signal.mitre_mapping:
                for mitre in signal.mitre_mapping:
                    if mitre.technique_id:
                        tech_node = create_technique_node(mitre.technique_id, mitre.tactic or "Unknown")
                        self._add_node(tech_node)
                        self._add_edge(link_technique_to_signal(tech_node.node_id, sig_node.node_id))
            
            # 4. Event Nodes & Edges
            sig_events = events_by_signal.get(str(signal.signal_id), [])
            for event in sig_events:
                evt_node = create_event_node(event)
                self._add_node(evt_node)
                self._add_edge(link_event_to_signal(evt_node.node_id, sig_node.node_id))
                
        # Persist Graph Components
        for node in self.nodes.values():
            await attack_graph_node_repository.create_or_update(self.db, node)
            
        for edge in self.edges:
            await attack_graph_edge_repository.create_or_update(self.db, edge)
            
        return list(self.nodes.values()), self.edges
