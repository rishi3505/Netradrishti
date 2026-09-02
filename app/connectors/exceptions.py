class ConnectorError(Exception):
    """Base exception for connector errors."""
    pass

class ValidationError(ConnectorError):
    """Raised when an event fails validation."""
    pass

class TransformationError(ConnectorError):
    """Raised when an event fails transformation."""
    pass

class ConnectorNotFoundError(ConnectorError):
    """Raised when a requested connector is not found in the registry."""
    pass
