from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.api.dependencies import get_db

router = APIRouter(prefix="/api/v1", tags=["Health"])

@router.get("/health")
async def health_check(db: AsyncSession = Depends(get_db)):
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
        await db.execute(text("SELECT 1"))
        health_status["components"]["database"] = "HEALTHY"
    except Exception as e:
        health_status["status"] = "DEGRADED"
        health_status["components"]["database"] = "UNAVAILABLE"
        
    return health_status
