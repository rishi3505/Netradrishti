from typing import Dict, Any, List
from app.schemas.ai_analysis import AIAnalysisResult

class AIResponseValidator:
    @staticmethod
    def validate(result: AIAnalysisResult, context: Dict[str, Any]) -> AIAnalysisResult:
        # Extract all valid IDs from context
        valid_ids = set()
        
        # Incident IDs
        if 'incident' in context and context['incident']:
            valid_ids.add(str(context['incident'].get('incident_id', '')))
            
        # Signal IDs
        for s in context.get('signals', []):
            if 'signal_id' in s:
                valid_ids.add(str(s['signal_id']))
                
        # Event IDs
        for e in context.get('events', []):
            if 'event_identity' in e and 'event_id' in e['event_identity']:
                valid_ids.add(str(e['event_identity']['event_id']))
        
        # Validate finding evidence_refs
        for finding in result.observations + result.inferences + result.possible_scenarios:
            invalid_refs = [ref for ref in finding.evidence_refs if ref not in valid_ids]
            if invalid_refs:
                # Remove hallucinated refs
                finding.evidence_refs = [ref for ref in finding.evidence_refs if ref in valid_ids]
                result.limitations.append(f"AI attempted to reference non-existent evidence IDs: {invalid_refs}. References were removed.")
                
        # Confidence validation is handled by Pydantic schema (ge=0, le=100) automatically on instantiation
        
        return result
