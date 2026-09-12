from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List
from app.detection.rules.registry import DetectionRuleRegistry
from app.schemas.detection import DetectionRuleSchema, DetectionRuleUpdate
from app.core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/detection", tags=["Detection"])

@router.get("/rules", response_model=List[DetectionRuleSchema])
async def list_rules(category: str = Query(None), enabled: bool = Query(None)):
    """
    List all registered detection rules.
    """
    rules = DetectionRuleRegistry.get_all_metadata()
    if category is not None:
        rules = [r for r in rules if r.category.lower() == category.lower()]
    if enabled is not None:
        rules = [r for r in rules if r.enabled == enabled]
    return rules

@router.get("/rules/{rule_id}", response_model=DetectionRuleSchema)
async def get_rule(rule_id: str):
    """
    Get a specific detection rule.
    """
    rule = DetectionRuleRegistry.get_rule_instance(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule.get_metadata()

@router.patch("/rules/{rule_id}", response_model=DetectionRuleSchema)
async def update_rule(rule_id: str, update: DetectionRuleUpdate):
    """
    Update configuration for a rule.
    """
    rule = DetectionRuleRegistry.get_rule_instance(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
        
    DetectionRuleRegistry.update_rule_config(rule_id, update.model_dump(exclude_unset=True))
    logger.info("Updated detection rule config", rule_id=rule_id)
    return rule.get_metadata()
