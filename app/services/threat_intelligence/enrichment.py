from typing import List, Optional
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.database_models import DBIncident, DBThreatIntelligence, DBIncidentIntelligence
from app.schemas.incident import Incident
from app.schemas.threat_intel import ThreatIntelligenceRequest, ThreatIntelligenceResult
from app.services.threat_intelligence.engine import engine

class EnrichmentService:
    async def enrich_incident(self, session: AsyncSession, incident_id: UUID) -> List[ThreatIntelligenceResult]:
        # 1. Load incident
        result = await session.execute(select(DBIncident).where(DBIncident.incident_id == incident_id))
        db_incident = result.scalar_one_or_none()
        if not db_incident:
            return []
            
        # 2. Extract IOCs
        # Simulating IOC extraction from incident_data.
        # This normally parses affected_entities, related events, etc.
        iocs_to_check = set()
        incident_data = db_incident.incident_data
        for entity in incident_data.get("affected_entities", []):
            iocs_to_check.add(entity)
            
        # 3. Lookup
        requests = [ThreatIntelligenceRequest(indicator=ioc) for ioc in iocs_to_check]
        ti_results = await engine.process_batch(requests)
        
        # 4. Store Evidence
        for ti in ti_results:
            # Store in threat_intelligence table
            db_ti = DBThreatIntelligence(
                id=ti.id,
                indicator=ti.indicator,
                normalized_indicator=ti.normalized_indicator,
                indicator_type=ti.indicator_type.value if ti.indicator_type else "unknown",
                verdict=ti.verdict.value,
                confidence=ti.confidence,
                provider=ti.provider,
                checked_at=ti.checked_at,
                intelligence_data=ti.dict()
            )
            session.add(db_ti)
            
            # Map to incident
            db_mapping = DBIncidentIntelligence(
                incident_id=incident_id,
                threat_intel_id=ti.id
            )
            session.add(db_mapping)
            
        await session.commit()
        return ti_results

enrichment_service = EnrichmentService()
