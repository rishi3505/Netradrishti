import hashlib
import json
from typing import Dict, Any, List

class IncidentContextBuilder:
    def __init__(self, max_signals: int = 50, max_events: int = 100):
        self.max_signals = max_signals
        self.max_events = max_events

    def build_context(self, incident: Any, signals: List[Any], events: List[Any], attack_graph: Dict[str, Any], risk_assessment: Any) -> Dict[str, Any]:
        """
        Builds a structured, bounded context for the AI provider, enforcing size limits.
        """
        context_truncated = False
        
        # Trim signals
        trimmed_signals = signals
        if len(signals) > self.max_signals:
            trimmed_signals = signals[:self.max_signals]
            context_truncated = True
            
        # Trim events
        trimmed_events = events
        if len(events) > self.max_events:
            trimmed_events = events[:self.max_events]
            context_truncated = True

        context = {
            "incident": incident.model_dump(mode='json') if hasattr(incident, 'model_dump') else incident,
            "signals": [s.model_dump(mode='json') if hasattr(s, 'model_dump') else s for s in trimmed_signals],
            "events": [e.model_dump(mode='json') if hasattr(e, 'model_dump') else e for e in trimmed_events],
            "attack_graph": attack_graph,
            "risk_assessment": risk_assessment.model_dump(mode='json') if hasattr(risk_assessment, 'model_dump') else risk_assessment,
            "context_truncated": context_truncated
        }
        return context

    def generate_hash(self, context: Dict[str, Any]) -> str:
        """
        Generates a deterministic hash of the bounded context.
        """
        context_str = json.dumps(context, sort_keys=True, default=str)
        return hashlib.sha256(context_str.encode('utf-8')).hexdigest()
