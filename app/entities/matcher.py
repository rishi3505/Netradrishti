from typing import Dict, Any, List, Tuple
from app.schemas.entity import ExtractedEntity, Entity

class EntityMatcher:
    def match(self, extracted: ExtractedEntity, candidate: Entity) -> Tuple[int, List[str]]:
        """
        Returns a tuple of (confidence_score, match_reasons)
        """
        score = 0
        reasons = []
        
        if extracted.entity_type != candidate.entity_type:
            return 0, ["Different entity types"]
            
        # Basic matching logic based on entity type
        if extracted.entity_type == "host":
            ext_device = extracted.attributes.get("device_id")
            ext_ip = extracted.attributes.get("ip")
            ext_mac = extracted.attributes.get("mac_address")
            
            cand_device = candidate.attributes.get("device_id")
            cand_ip = candidate.attributes.get("ip")
            cand_mac = candidate.attributes.get("mac_address")
            
            if ext_device and cand_device and ext_device == cand_device:
                score += 100
                reasons.append("Same unique device_id")
                return score, reasons # Fast track
                
            if extracted.normalized_value == candidate.normalized_value:
                score += 50
                reasons.append("Same canonical hostname")
                
                if ext_ip and cand_ip and ext_ip == cand_ip:
                    score += 30
                    reasons.append("Same IP address")
                    
                if ext_mac and cand_mac and ext_mac == cand_mac:
                    score += 45
                    reasons.append("Same MAC address")
            else:
                # Different hostname, but maybe same IP?
                if ext_ip and cand_ip and ext_ip == cand_ip:
                    score += 40
                    reasons.append("Same IP address only")
                    
        elif extracted.entity_type == "user":
            if extracted.normalized_value == candidate.normalized_value:
                score += 85
                reasons.append("Same Username + Domain")
                
        elif extracted.entity_type == "ip":
            if extracted.normalized_value == candidate.normalized_value:
                score += 100
                reasons.append("Exact IP match")
                
        elif extracted.entity_type == "file":
            if extracted.normalized_value == candidate.normalized_value:
                score += 100
                reasons.append("Exact Hash match")
                
        elif extracted.entity_type == "domain":
            if extracted.normalized_value == candidate.normalized_value:
                score += 100
                reasons.append("Exact Domain match")
                
        # Base fallback
        if score == 0 and extracted.normalized_value == candidate.normalized_value:
            score += 50
            reasons.append("Exact value match")
            
        return score, reasons
