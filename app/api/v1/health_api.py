from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.core.database import get_db

router = APIRouter(prefix="/api/v1", tags=["Health"])

@router.get("/health")
def health_check(db: Session = Depends(get_db)):
    health_status = {
        "status": "HEALTHY",
        "components": {
            "api": "HEALTHY",
            "database": "UNKNOWN",
            "ingestion": "HEALTHY",
            "ai_provider": "HEALTHY"
        }
    }
    
    try:
        db.execute(text("SELECT 1"))
        health_status["components"]["database"] = "HEALTHY"
    except Exception as e:
        health_status["status"] = "DEGRADED"
        health_status["components"]["database"] = "UNAVAILABLE"
        
    return health_status
