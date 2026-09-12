from typing import Dict, List, Type, Optional
from app.detection.rules.base import DetectionRule
from app.schemas.detection import DetectionRuleSchema

class DetectionRuleRegistry:
    """
    Registry for managing detection rules.
    """
    _rules: Dict[str, Type[DetectionRule]] = {}
    _instances: Dict[str, DetectionRule] = {}

    @classmethod
    def register(cls, rule_class: Type[DetectionRule]):
        metadata = rule_class.get_metadata()
        cls._rules[metadata.rule_id] = rule_class
        cls._instances[metadata.rule_id] = rule_class()
        return rule_class

    @classmethod
    def get_rule_class(cls, rule_id: str) -> Optional[Type[DetectionRule]]:
        return cls._rules.get(rule_id)

    @classmethod
    def get_rule_instance(cls, rule_id: str) -> Optional[DetectionRule]:
        return cls._instances.get(rule_id)

    @classmethod
    def get_all_rules(cls) -> List[DetectionRule]:
        return list(cls._instances.values())

    @classmethod
    def get_all_metadata(cls) -> List[DetectionRuleSchema]:
        return [rule.get_metadata() for rule in cls._instances.values()]

    @classmethod
    def update_rule_config(cls, rule_id: str, new_config: dict):
        if rule_id in cls._instances:
            rule = cls._instances[rule_id]
            # Update specific config attributes
            for k, v in new_config.items():
                if hasattr(rule.config, k):
                    setattr(rule.config, k, v)
