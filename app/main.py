from fastapi import FastAPI
from app.core.config import settings
from app.core.logging import setup_logging, get_logger
from app.api.routes import health, events, ingestion, sources
from app.connectors.manager import connector_manager

# Initialize logging
setup_logging()
logger = get_logger(__name__)

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Netradhrishti - Intelligent Security Correlation and Attack Analysis Platform",
    version="1.0.0",
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

# Include routers
app.include_router(health.router, tags=["Health"])
app.include_router(events.router, prefix=settings.API_V1_STR, tags=["Events"])
app.include_router(ingestion.router, prefix=f"{settings.API_V1_STR}/ingestion", tags=["Ingestion"])
app.include_router(sources.router, prefix=f"{settings.API_V1_STR}/sources", tags=["Sources"])

# Import Module 4 & 5 routers here to avoid circular imports during app init if any
from app.api.routes import detection, signals, correlation, incidents
app.include_router(detection.router, prefix=f"{settings.API_V1_STR}", tags=["Detection"])
app.include_router(signals.router, prefix=f"{settings.API_V1_STR}", tags=["Signals"])
app.include_router(correlation.router, prefix=f"{settings.API_V1_STR}", tags=["Correlation"])
app.include_router(incidents.router, prefix=f"{settings.API_V1_STR}", tags=["Incidents"])

@app.on_event("startup")
async def startup_event():
    logger.info("Starting up Netradhrishti Backend")
    connector_manager.initialize_connectors()

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down Netradhrishti Backend")
