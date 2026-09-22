import os

class Settings:
    PROJECT_NAME: str = "Netradhrishti"
    API_V1_STR: str = "/api/v1"
    SQLALCHEMY_DATABASE_URI: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./netradrishti.db")
    
    # Threat Intelligence Settings
    THREAT_INTEL_ENABLED: bool = os.getenv("THREAT_INTEL_ENABLED", "True").lower() in ("true", "1", "yes")
    THREAT_INTEL_PROVIDER: str = os.getenv("THREAT_INTEL_PROVIDER", "mock")
    THREAT_INTEL_API_KEY: str = os.getenv("THREAT_INTEL_API_KEY", "")
    THREAT_INTEL_TIMEOUT: int = int(os.getenv("THREAT_INTEL_TIMEOUT", "10"))
    THREAT_INTEL_CACHE_TTL_SECONDS: int = int(os.getenv("THREAT_INTEL_CACHE_TTL_SECONDS", "3600"))

settings = Settings()
