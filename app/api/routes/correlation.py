from fastapi import APIRouter, HTTPException
from typing import List
from app.correlation.rules.registry import CorrelationRuleRegistry
from app.schemas.correlation import CorrelationRuleSchema, CorrelationRuleUpdate
from app.core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/correlation", tags=["Correlation"])

@router.get("/rules", response_model=List[CorrelationRuleSchema])
async def list_correlation_rules():
    """
    List all registered correlation rules.
    """
    return CorrelationRuleRegistry.get_all_metadata()

@router.post("/rules/{rule_id}/enable", response_model=CorrelationRuleSchema)
async def enable_rule(rule_id: str):
    rule = CorrelationRuleRegistry.get_rule_instance(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
        
    CorrelationRuleRegistry.update_rule_config(rule_id, {"enabled": True})
    return rule.get_metadata()

@router.post("/rules/{rule_id}/disable", response_model=CorrelationRuleSchema)
async def disable_rule(rule_id: str):
    rule = CorrelationRuleRegistry.get_rule_instance(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
        
    CorrelationRuleRegistry.update_rule_config(rule_id, {"enabled": False})
    return rule.get_metadata()
