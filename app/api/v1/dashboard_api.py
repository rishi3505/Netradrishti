from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, select
from typing import Dict, Any

from app.api.dependencies import get_db
from app.core.auth import require_role, get_current_user
from app.models.database_models import DBIncident, DBUnifiedSecurityEvent, DBSecuritySignal, DBThreatIntelligence

router = APIRouter(prefix="/api/v1/dashboard", tags=["Dashboard"])

@router.get("/overview")
async def get_dashboard_overview(
    db: AsyncSession = Depends(get_db),
    user: Dict = Depends(require_role(["ANALYST", "RESPONDER", "ADMIN"]))
) -> Dict[str, Any]:
    
    total_incidents = await db.scalar(select(func.count()).select_from(DBIncident))
    open_incidents = await db.scalar(select(func.count()).select_from(DBIncident).filter(DBIncident.status.in_(["new", "investigating"])))
    critical_incidents = await db.scalar(select(func.count()).select_from(DBIncident).filter(DBIncident.severity == "critical"))
    
    total_events = await db.scalar(select(func.count()).select_from(DBUnifiedSecurityEvent))
    suspicious_signals = await db.scalar(select(func.count()).select_from(DBSecuritySignal))
    
    ti_matches = await db.scalar(select(func.count()).select_from(DBThreatIntelligence).filter(DBThreatIntelligence.verdict == "malicious"))

    return {
        "security_overview": {
            "total_events": total_events or 0,
            "suspicious_signals": suspicious_signals or 0,
            "open_incidents": open_incidents or 0,
            "critical_incidents": critical_incidents or 0
        },
        "threat_intelligence": {
            "malicious_indicators": ti_matches or 0
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
