# Netradhrishti

Netradhrishti is an Intelligent Security Correlation, Threat Intelligence, Attack Analysis, and Incident Response Guidance Platform.

## Features (Module 1 & 2)
- FastAPI Backend & PostgreSQL Integration
- Unified Security Event Schema & Event Ingestion API
- **Module 2: Data Ingestion & Connector Framework**
  - Plug-in style connector framework (Windows, Firewall, Suricata, SurakshaNetra)
  - Single and Batch event ingestion APIs (`/api/v1/ingestion/events`)
  - Dynamic Connector Registry and source validation
  - In-flight raw event transformation and evidence preservation


## Setup

1. **Environment Configuration**
   Copy `.env.example` to `.env`.

2. **Docker Compose (Recommended)**
   ```bash
   docker-compose up --build
   ```

3. **Running locally (Without Docker)**
   ```bash
   pip install -r requirements.txt
   uvicorn app.main:app --reload
   ```

## API Documentation
Once running, visit `http://localhost:8000/docs` to see the interactive OpenAPI documentation.
