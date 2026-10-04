from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import Dict, Any, List
from app.core.database import get_db
from app.core.auth import require_role
from app.models.database_models import DBAuditLog

router = APIRouter(prefix="/api/v1/audit", tags=["Audit Logs"])

@router.get("/")
def get_audit_logs(
    limit: int = Query(50, le=100),
    offset: int = 0,
    db: Session = Depends(get_db),
    user: Dict = Depends(require_role(["ADMIN"]))
) -> List[Dict[str, Any]]:
    
    logs = db.query(DBAuditLog).order_by(DBAuditLog.timestamp.desc()).offset(offset).limit(limit).all()
    
    return [
        {
            "log_id": str(log.log_id),
            "actor": log.actor,
            "action": log.action,
            "object_id": log.object_id,
            "previous_state": log.previous_state,
            "new_state": log.new_state,
            "request_id": log.request_id,
            "timestamp": log.timestamp.isoformat()
        } for log in logs
    ]
