from typing import Dict, Type
from app.connectors.base import BaseConnector
from app.connectors.exceptions import ConnectorNotFoundError

class ConnectorRegistry:
    """
    Registry for dynamic lookup of connectors based on source_type.
    """
    def __init__(self):
        self._connectors: Dict[str, BaseConnector] = {}

    def register(self, source_type: str, connector_instance: BaseConnector):
        """Register an initialized connector instance."""
        self._connectors[source_type] = connector_instance

    def get_connector(self, source_type: str) -> BaseConnector:
        """Get a connector by source_type."""
        if source_type not in self._connectors:
            raise ConnectorNotFoundError(f"Connector for source_type '{source_type}' not found.")
        return self._connectors[source_type]
    
    def list_connectors(self) -> Dict[str, Dict]:
        """List all registered connectors and their metadata."""
        return {
            source_type: connector.get_source_metadata() 
            for source_type, connector in self._connectors.items()
        }

    def connector_exists(self, source_type: str) -> bool:
        """Check if a connector is registered."""
        return source_type in self._connectors

connector_registry = ConnectorRegistry()
