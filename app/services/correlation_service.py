from sqlalchemy.ext.asyncio import AsyncSession
from app.schemas.signal import SecuritySignal
from app.correlation.engine import CorrelationEngine
from app.correlation.context import CorrelationContext
from app.correlation.deduplication import IncidentDeduplicator
from app.services.incident_service import incident_service
from app.core.logging import get_logger

logger = get_logger(__name__)

class CorrelationService:
    def __init__(self):
        pass

    async def process_correlation(self, db: AsyncSession, new_signal: SecuritySignal):
        """
        Runs the correlation engine against a new signal and persists any resulting incidents.
        """
        logger.info("Running correlation for signal", signal_id=str(new_signal.signal_id))
        
        engine = CorrelationEngine()
        context = CorrelationContext(db)
        deduplicator = IncidentDeduplicator(db)
        
        # 1. Run engine to get candidate incidents
        incidents = await engine.analyze(new_signal, context)
        
        for incident in incidents:
            try:
                # 2. Deduplication check
                duplicate_db_inc = await deduplicator.find_existing_incident(incident)
                
                if duplicate_db_inc:
                    # Update existing incident
                    logger.info("Found duplicate incident, merging", incident_id=str(duplicate_db_inc.incident_id))
                    merged_db_inc = await deduplicator.merge_incidents(duplicate_db_inc, incident)
                    await incident_service.update_incident(db, duplicate_db_inc, Incident(**merged_db_inc.incident_data))
                else:
                    # Create new incident
                    logger.info("Creating new incident", incident_title=incident.title)
                    await incident_service.create_incident(db, incident)
            except Exception as e:
                logger.error("Failed to process incident", error=str(e), title=incident.title)

correlation_service = CorrelationService()
