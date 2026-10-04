import asyncio
import uuid
import json
from datetime import datetime
from sqlalchemy.orm import Session
from app.core.database import SessionLocal, engine
from app.models.database_models import (
    Base, DBUnifiedSecurityEvent, DBSecuritySignal, DBIncident, 
    DBThreatIntelligence, DBAttackGraphNode, DBAttackGraphEdge,
    DBRiskAssessment, DBAIAnalysis, DBResponsePlan
)

def run_demo():
    print("Initializing demo environment...")
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    
    try:
        print("Seeding authentication attack...")
        event_id_1 = uuid.uuid4()
        inc_id = uuid.uuid4()

        # Insert Incident
        incident = DBIncident(
            incident_id=inc_id,
            title="Suspicious Network & Authentication Activity",
            status="NEW",
            severity="HIGH",
            incident_data={
                "incident_id": str(inc_id),
                "title": "Suspicious Network & Authentication Activity",
                "severity": "high",
                "status": "new",
                "confidence": 93,
                "risk_score": 87
            }
        )
        db.add(incident)

        # Insert Threat Intel
        ti_id = uuid.uuid4()
        ti = DBThreatIntelligence(
            id=ti_id,
            indicator="198.51.100.33",
            normalized_indicator="198.51.100.33",
            indicator_type="IP",
            verdict="malicious",
            confidence={"score": 92},
            provider="Demo Intel",
            intelligence_data={"malware": "unknown C2"}
        )
        db.add(ti)

        # Insert AI Analysis
        ai = DBAIAnalysis(
            analysis_id=uuid.uuid4(),
            incident_id=str(inc_id),
            context_hash="demo",
            provider="Demo AI",
            status="COMPLETED",
            analysis_data={
                "summary": "Post-authentication execution.",
                "observed": ["PowerShell execution", "Authentication failures"],
                "inferred": ["Activity appears related to the authentication event."]
            }
        )
        db.add(ai)

        db.commit()
        print("Demo seed completed successfully. Incident INC-" + str(inc_id) + " created.")
        
    except Exception as e:
        print(f"Error during seeding: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    run_demo()
