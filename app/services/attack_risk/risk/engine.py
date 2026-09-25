from typing import List
from sqlalchemy.ext.asyncio import AsyncSession
from app.schemas.incident import Incident
from app.schemas.signal import SecuritySignal
from app.schemas.attack_graph import RiskAssessment
from app.services.attack_risk.risk.factors import (
    calculate_severity_factor,
    calculate_source_diversity_factor,
    calculate_technique_diversity_factor,
    calculate_threat_intel_factor
)
from app.services.attack_risk.risk.scoring import calculate_total_score, map_score_to_level
from app.services.attack_risk.graph.traversal import GraphTraversalEngine
from app.services.attack_risk.explanations import generate_explanation
from app.repositories.risk_repository import risk_assessment_repository

class RiskEngine:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.traversal_engine = GraphTraversalEngine(db)

    async def calculate_risk(self, incident: Incident, signals: List[SecuritySignal]) -> RiskAssessment:
        # 1. Calculate explicit factors
        factors = [
            calculate_severity_factor(incident, signals),
            calculate_source_diversity_factor(signals),
            calculate_technique_diversity_factor(signals),
            calculate_threat_intel_factor(signals)
        ]
        
        # 2. Extract Paths
        paths = await self.traversal_engine.get_incident_attack_paths(str(incident.incident_id))
        
        # 3. Calculate Scores
        total_score = calculate_total_score(factors)
        risk_level = map_score_to_level(total_score)
        
        # 4. Generate Explanations
        # explanation = generate_explanation(factors, paths) # Not strictly on RiskAssessment schema yet, but can be added or just derived
        
        # Gather techniques and affected entities
        techniques = set()
        for s in signals:
            if hasattr(s, 'mitre_mapping') and s.mitre_mapping:
                for m in s.mitre_mapping:
                    if m.technique_id: techniques.add(m.technique_id)
                    
        # Assuming incident has affected_entities or derived from signals
        entities = set()
        for s in signals:
            if hasattr(s, 'affected_entities') and s.affected_entities:
                for e in s.affected_entities:
                    entities.add(str(e))
        
        # 5. Build RiskAssessment
        assessment = RiskAssessment(
            incident_id=str(incident.incident_id),
            risk_score=total_score,
            risk_level=risk_level,
            confidence=incident.confidence if hasattr(incident, 'confidence') else 80,
            factors=factors,
            attack_paths=paths,
            techniques=list(techniques),
            affected_entities=list(entities),
            evidence_count=len(signals), # Rough proxy
            model_version="v1"
        )
        
        # 6. Save Assessment
        await risk_assessment_repository.create(self.db, assessment)
        
        return assessment
