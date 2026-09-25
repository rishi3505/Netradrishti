from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Any
import logging

from app.schemas.ai_analysis import AIAnalysisRecord, AIAnalysisStatus, AIProviderConfig
from app.repositories.ai_analysis_repository import ai_analysis_repository
from app.services.ai_analysis.context_builder import IncidentContextBuilder
from app.services.ai_analysis.prompt_builder import PromptBuilder, AI_ANALYSIS_PROMPT_VERSION
from app.services.ai_analysis.validators import AIResponseValidator
from app.services.ai_analysis.registry import ai_provider_registry
from app.services.ai_analysis.safety import SafetySanitizer

logger = logging.getLogger(__name__)

class AIAnalysisEngine:
    def __init__(self, db: AsyncSession, config: AIProviderConfig):
        self.db = db
        self.config = config
        self.context_builder = IncidentContextBuilder()

    async def analyze_incident(self, incident: Any, signals: List[Any], events: List[Any], attack_graph: dict, risk_assessment: Any, force_reanalyze: bool = False) -> AIAnalysisRecord:
        
        if not self.config.enabled:
            raise ValueError("AI Analysis is globally disabled.")

        # 1. Build and sanitize Context
        context = self.context_builder.build_context(incident, signals, events, attack_graph, risk_assessment)
        context = SafetySanitizer.sanitize_context(context)
        context_hash = self.context_builder.generate_hash(context)
        
        incident_id = str(incident.incident_id)
        
        # 2. Check Cache
        if not force_reanalyze:
            existing = await ai_analysis_repository.get_by_incident_and_hash(self.db, incident_id, context_hash)
            if existing and existing.status == AIAnalysisStatus.COMPLETED.value:
                logger.info(f"Returning cached AI analysis for incident {incident_id}")
                return AIAnalysisRecord(**existing.analysis_data)
                
        # 3. Create Analysis Record (PENDING/RUNNING)
        record = AIAnalysisRecord(
            incident_id=incident_id,
            provider=self.config.provider_name,
            model=self.config.model_name,
            prompt_version=AI_ANALYSIS_PROMPT_VERSION,
            context_hash=context_hash,
            status=AIAnalysisStatus.RUNNING
        )
        db_record = await ai_analysis_repository.create(self.db, record)
        
        try:
            # 4. Prompt & Analyze
            prompt = PromptBuilder.build_prompt(context)
            provider = ai_provider_registry.get_provider(self.config.provider_name, self.config.model_dump())
            
            # In a real async setup, we'd enqueue this or wrap in timeout.
            raw_result = await provider.analyze(context, prompt)
            
            # 5. Validate Output
            validated_result = AIResponseValidator.validate(raw_result, context)
            
            # 6. Finalize Record
            record.status = AIAnalysisStatus.COMPLETED
            record.result = validated_result
            
            await ai_analysis_repository.update(self.db, db_record, record)
            return record
            
        except Exception as e:
            logger.error(f"AI Analysis failed: {str(e)}")
            record.status = AIAnalysisStatus.FAILED
            record.error_info = str(e)
            await ai_analysis_repository.update(self.db, db_record, record)
            return record
