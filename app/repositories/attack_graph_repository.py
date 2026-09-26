from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from typing import Optional, List, Any
import uuid
from app.repositories.base_repository import BaseRepository
from app.models.database_models import DBAttackGraphNode, DBAttackGraphEdge
from app.schemas.attack_graph import AttackGraphNode, AttackGraphEdge

class AttackGraphNodeRepository(BaseRepository[DBAttackGraphNode, AttackGraphNode, AttackGraphNode]):
    def __init__(self):
        super().__init__(DBAttackGraphNode)

    async def get_by_node_id(self, db: AsyncSession, node_id: str) -> Optional[DBAttackGraphNode]:
        query = select(DBAttackGraphNode).where(DBAttackGraphNode.node_id == node_id)
        result = await db.execute(query)
        return result.scalar_one_or_none()

    async def create_or_update(self, db: AsyncSession, obj_in: AttackGraphNode) -> DBAttackGraphNode:
        existing = await self.get_by_node_id(db, obj_in.node_id)
        if existing:
            existing.node_data = obj_in.model_dump(mode="json")
            if obj_in.timestamp:
                existing.timestamp = obj_in.timestamp
            await db.commit()
            await db.refresh(existing)
            return existing
            
        db_obj = DBAttackGraphNode(
            node_id=obj_in.node_id,
            node_type=obj_in.node_type.value if hasattr(obj_in.node_type, "value") else obj_in.node_type,
            timestamp=obj_in.timestamp,
            node_data=obj_in.model_dump(mode="json")
        )
        db.add(db_obj)
        await db.commit()
        await db.refresh(db_obj)
        return db_obj

class AttackGraphEdgeRepository(BaseRepository[DBAttackGraphEdge, AttackGraphEdge, AttackGraphEdge]):
    def __init__(self):
        super().__init__(DBAttackGraphEdge)

    async def get_by_endpoints(self, db: AsyncSession, source_node: str, destination_node: str, relationship_type: str) -> Optional[DBAttackGraphEdge]:
        query = select(DBAttackGraphEdge).where(
            and_(
                DBAttackGraphEdge.source_node == source_node,
                DBAttackGraphEdge.destination_node == destination_node,
                DBAttackGraphEdge.relationship_type == relationship_type
            )
        )
        result = await db.execute(query)
        return result.scalar_one_or_none()
        
    async def get_edges_for_node(self, db: AsyncSession, node_id: str) -> List[DBAttackGraphEdge]:
        query = select(DBAttackGraphEdge).where(
            (DBAttackGraphEdge.source_node == node_id) | (DBAttackGraphEdge.destination_node == node_id)
        )
        result = await db.execute(query)
        return result.scalars().all()

    async def create_or_update(self, db: AsyncSession, obj_in: AttackGraphEdge) -> DBAttackGraphEdge:
        rel_type = obj_in.relationship_type.value if hasattr(obj_in.relationship_type, "value") else obj_in.relationship_type
        existing = await self.get_by_endpoints(db, obj_in.source_node, obj_in.destination_node, rel_type)
        if existing:
            # Merge evidence if necessary or simply update
            existing.edge_data = obj_in.model_dump(mode="json")
            if obj_in.timestamp:
                existing.timestamp = obj_in.timestamp
            await db.commit()
            await db.refresh(existing)
            return existing
            
        db_obj = DBAttackGraphEdge(
            edge_id=obj_in.edge_id,
            source_node=obj_in.source_node,
            destination_node=obj_in.destination_node,
            relationship_type=rel_type,
            timestamp=obj_in.timestamp,
            edge_data=obj_in.model_dump(mode="json")
        )
        db.add(db_obj)
        await db.commit()
        await db.refresh(db_obj)
        return db_obj

attack_graph_node_repository = AttackGraphNodeRepository()
attack_graph_edge_repository = AttackGraphEdgeRepository()
