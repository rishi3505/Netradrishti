from sqlalchemy import Column, String, DateTime, ForeignKey, Integer, JSON, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
from app.core.database import Base # Assuming this exists based on module 1

class EntityModel(Base):
    __tablename__ = "entities"

    entity_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_type = Column(String, index=True)
    value = Column(String, index=True)
    normalized_value = Column(String, index=True)
    attributes = Column(JSON, default=dict)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    # Relationships
    aliases = relationship("EntityAliasModel", back_populates="entity", cascade="all, delete-orphan")
    identifiers = relationship("EntityIdentifierModel", back_populates="entity", cascade="all, delete-orphan")

class EntityAliasModel(Base):
    __tablename__ = "entity_aliases"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(UUID(as_uuid=True), ForeignKey("entities.entity_id"))
    alias_value = Column(String)
    alias_type = Column(String)
    normalized_value = Column(String, index=True)
    source = Column(String)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    entity = relationship("EntityModel", back_populates="aliases")

class EntityIdentifierModel(Base):
    __tablename__ = "entity_identifiers"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id = Column(UUID(as_uuid=True), ForeignKey("entities.entity_id"))
    identifier_type = Column(String)
    value = Column(String)
    normalized_value = Column(String, index=True)
    confidence = Column(Integer)
    source = Column(String)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    entity = relationship("EntityModel", back_populates="identifiers")
