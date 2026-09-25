from typing import Any, Dict
from app.services.ai_analysis.providers.base import AIAnalysisProvider
from app.schemas.ai_analysis import (
    AIAnalysisResult, AIAnalysisFinding, AIAnalysisFindingType, AIAnalysisAssessment,
    AIAnalysisRecommendation, AIRecommendationCategory, AIAnalysisMissingEvidence,
    AIAnalysisTechnique
)

class MockAIProvider(AIAnalysisProvider):
    async def analyze(self, context: Dict[str, Any], prompt: str) -> AIAnalysisResult:
        """
        Deterministic mock that always returns a predictable structure, heavily relying on the input context.
        """
        # Parse context to dynamically generate deterministic references
        incident_id = context.get('incident', {}).get('incident_id', 'unknown')
        signals = context.get('signals', [])
        sig_ids = [str(s.get('signal_id')) for s in signals] if signals else []
        
        return AIAnalysisResult(
            summary=f"Incident {incident_id} exhibits signs of sequential suspicious activity.",
            assessment=AIAnalysisAssessment(
                statement="Multiple indicators suggest an attack progression, but more endpoint context is needed for certainty.",
                confidence=75
            ),
            observations=[
                AIAnalysisFinding(
                    statement="Observed malicious signals associated with the incident.",
                    type=AIAnalysisFindingType.OBSERVED,
                    confidence=90,
                    evidence_refs=sig_ids[:1] if sig_ids else []
                )
            ],
            inferences=[
                AIAnalysisFinding(
                    statement="Sequential execution indicates likely post-authentication activity.",
                    type=AIAnalysisFindingType.INFERRED,
                    confidence=70,
                    evidence_refs=sig_ids
                )
            ],
            possible_scenarios=[
                AIAnalysisFinding(
                    statement="Possible credential compromise followed by C2 execution.",
                    type=AIAnalysisFindingType.POSSIBLE,
                    confidence=60,
                    evidence_refs=sig_ids
                )
            ],
            techniques=[
                AIAnalysisTechnique(
                    technique_id="T1078",
                    name="Valid Accounts",
                    evidence_refs=[]
                )
            ],
            important_entities=["mock_user", "mock_host"],
            important_indicators=["192.168.1.100"],
            investigation_questions=[
                "Was the account legitimately used at this time?",
                "What was the parent process?"
            ],
            recommendations=[
                AIAnalysisRecommendation(
                    category=AIRecommendationCategory.INVESTIGATE,
                    recommendation="Review authentication logs for anomalous locations.",
                    reason="To determine if the session was hijacked.",
                    evidence_refs=[]
                ),
                AIAnalysisRecommendation(
                    category=AIRecommendationCategory.EVIDENCE_COLLECTION,
                    recommendation="Collect the process tree for the affected host.",
                    reason="Needed to validate process execution chain.",
                    evidence_refs=[]
                )
            ],
            missing_evidence=[
                AIAnalysisMissingEvidence(
                    item="Parent process",
                    reason="Needed to validate process execution chain."
                )
            ],
            limitations=[
                "Analysis limited by available endpoint telemetry."
            ]
        )

    async def is_healthy(self) -> bool:
        return True
