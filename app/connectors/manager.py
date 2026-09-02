from app.connectors.registry import connector_registry
from app.connectors.windows.connector import WindowsConnector
from app.connectors.firewall.connector import FirewallConnector
from app.connectors.suricata.connector import SuricataConnector
from app.connectors.surakshanetra.connector import SurakshaNetraConnector
from app.core.logging import get_logger

logger = get_logger(__name__)

class ConnectorManager:
    def __init__(self):
        self._initialized = False

    def initialize_connectors(self):
        if self._initialized:
            return
            
        logger.info("Initializing connector registry")
        connector_registry.register("windows", WindowsConnector())
        connector_registry.register("firewall", FirewallConnector())
        connector_registry.register("suricata", SuricataConnector())
        connector_registry.register("surakshanetra", SurakshaNetraConnector())
        
        self._initialized = True
        logger.info(f"Registered {len(connector_registry.list_connectors())} connectors.")

    def get_registry(self):
        return connector_registry

connector_manager = ConnectorManager()
