from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Dict, Any

from app.core.database import get_db
from app.core.auth import require_role, get_current_user
from app.models.database_models import DBIncident, DBUnifiedSecurityEvent, DBSecuritySignal, DBThreatIntelligence

router = APIRouter(prefix="/api/v1/dashboard", tags=["Dashboard"])

@router.get("/overview")
def get_dashboard_overview(
    db: Session = Depends(get_db),
    user: Dict = Depends(require_role(["ANALYST", "RESPONDER", "ADMIN"]))
) -> Dict[str, Any]:
    
    # Example metrics queries (in a real scenario, use async DB calls or optimize indexing)
    total_incidents = db.query(DBIncident).count()
    open_incidents = db.query(DBIncident).filter(DBIncident.status.in_(["new", "investigating"])).count()
    critical_incidents = db.query(DBIncident).filter(DBIncident.severity == "critical").count()
    
    total_events = db.query(DBUnifiedSecurityEvent).count()
    suspicious_signals = db.query(DBSecuritySignal).count()
    
    ti_matches = db.query(DBThreatIntelligence).filter(DBThreatIntelligence.verdict == "malicious").count()

    return {
        "security_overview": {
            "total_events": total_events,
            "suspicious_signals": suspicious_signals,
            "open_incidents": open_incidents,
            "critical_incidents": critical_incidents
        },
        "threat_intelligence": {
            "malicious_indicators": ti_matches
        },
        "system_health": {
            "status": "HEALTHY",
            "components": {
                "database": "HEALTHY",
                "api": "HEALTHY",
                "ingestion": "HEALTHY"
            }
        }
    }
