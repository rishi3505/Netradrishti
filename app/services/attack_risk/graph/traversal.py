from typing import List, Dict
from app.schemas.attack_graph import AttackGraphNode, AttackGraphEdge, AttackPath
from sqlalchemy.ext.asyncio import AsyncSession
from app.repositories.attack_graph_repository import attack_graph_node_repository, attack_graph_edge_repository

class GraphTraversalEngine:
    def __init__(self, db: AsyncSession):
        self.db = db
        
    async def get_incident_attack_paths(self, incident_id: str) -> List[AttackPath]:
        # This is a deterministic traversal pulling signals related to an incident
        # In a real environment, this would do a recursive graph query (e.g. CTE in Postgres or NetworkX)
        # For Netradhrishti, we will return a deterministic sequential path of the signals.
        
        # Load incident node
        incident_node = await attack_graph_node_repository.get_by_node_id(self.db, f"incident-{incident_id}")
        if not incident_node:
            return []
            
        # Get edges attached to incident
        edges_db = await attack_graph_edge_repository.get_edges_for_node(self.db, f"incident-{incident_id}")
        
        # Resolve Pydantic schemas from DB models
        from app.schemas.attack_graph import AttackGraphEdge, AttackGraphNode
        edges = [AttackGraphEdge(**e.edge_data) for e in edges_db]
        
        # Find signal nodes
        signal_node_ids = [e.source_node for e in edges if e.source_node.startswith('signal-')]
        
        nodes = []
        path_edges = list(edges) # shallow copy
        
        for n_id in signal_node_ids:
            db_node = await attack_graph_node_repository.get_by_node_id(self.db, n_id)
            if db_node:
                nodes.append(AttackGraphNode(**db_node.node_data))
                # Also fetch temporal edges between signals
                sig_edges = await attack_graph_edge_repository.get_edges_for_node(self.db, n_id)
                for se in sig_edges:
                    e_schema = AttackGraphEdge(**se.edge_data)
                    if e_schema.relationship_type.value == "preceded":
                        path_edges.append(e_schema)
        
        # Sort nodes temporally
        nodes = sorted([n for n in nodes if n.timestamp], key=lambda x: x.timestamp)
        
        # If there are no signals, there is no path.
        if not nodes:
            return []
            
        path = AttackPath(
            incident_id=incident_id,
            nodes=nodes,
            edges=path_edges,
            confidence=85,
            explanation="Sequential attack path extracted from temporal relationships of related signals."
        )
        
        return [path]
