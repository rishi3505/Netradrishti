# Module 2: Data Ingestion & Connector Framework

## Overview
Netradhrishti's ingestion framework handles the receiving, validation, and transformation of security telemetry from diverse sources into a standard `UnifiedSecurityEvent`. The core design treats all external tools as independent sources, ensuring modularity and easy extensibility.

## Architecture
The connector architecture leverages a registry and an abstraction layer:
- **BaseConnector**: Defines standard interfaces (`validate_raw_event`, `transform`, `get_source_metadata`, `health_check`).
- **ConnectorRegistry**: Dynamically tracks available connectors by `source_type`.
- **ConnectorManager**: Initializes and manages the lifecycle of the connectors.
- **IngestionService**: Orchestrates the API requests by mapping source types to the correct connector, performing validation, processing transformations, and relaying events to the Module 1 Pipeline Service.

## Supported Reference Connectors
1. **Windows**: Transforms Windows Security Events (e.g., 4624, 4625, 4634) to generic authentication events.
2. **Firewall**: Accepts structured firewall logs (allowed/blocked actions).
3. **Suricata**: Maps Suricata IDS alerts into security contexts with severity mapping.
4. **SurakshaNetra**: First-class connector preserving detection confidence, affected entities, and metadata. Treated as a telemetry source rather than a core dependency.

## Event Flow
```text
Source -> Ingestion API (Single/Batch)
         -> Ingestion Service
             -> ConnectorRegistry (find connector)
                 -> Connector.transform (validation + mapping)
                     -> UnifiedSecurityEvent
                         -> PipelineService (Module 1 processing)
                             -> Persistence (EventService)
```

## API Endpoints

### Ingestion
- `POST /api/v1/ingestion/events`: Submits a single event payload.
- `POST /api/v1/ingestion/events/batch`: Submits an array of event payloads (returns partial failures if applicable).

**Example Single Event Request:**
```json
{
  "source_type": "firewall",
  "raw_event": {
    "timestamp": "2026-09-02T10:00:00Z",
    "src_ip": "192.168.1.10",
    "src_port": 54321,
    "dst_ip": "10.0.0.10",
    "dst_port": 443,
    "protocol": "TCP",
    "action": "allowed"
  }
}
```

### Sources
- `GET /api/v1/sources`: Lists all registered sources.
- `GET /api/v1/sources/connectors`: Lists available connectors in the registry.
- `GET /api/v1/sources/{source_id}`: Retrieves specific source information.
- `GET /api/v1/sources/connectors/{source_type}/health`: Checks the health of a given connector type.

## How to Add a New Connector
1. **Create Directory**: Add a directory under `app/connectors/` (e.g., `app/connectors/aws/`).
2. **Implement BaseConnector**: Create `connector.py` and implement the `BaseConnector` interface (`validate_raw_event`, `transform`, etc.).
3. **Handle Errors**: Raise `ValidationError` or `TransformationError` if transformation fails.
4. **Preserve Raw Event**: Ensure the `UnifiedSecurityEvent.raw` field contains the unaltered source event data.
5. **Register Connector**: Open `app/connectors/manager.py` and register the new instance in `initialize_connectors()`.
6. **Add Tests**: Write validation and transformation tests in `tests/test_connectors.py`.
