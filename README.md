# Netradhrishti

Netradhrishti is an Intelligent Security Correlation, Threat Intelligence, Attack Analysis, and Incident Response Guidance Platform.

## Features (Module 1)
- FastAPI Backend
- PostgreSQL Integration
- Unified Security Event Schema
- Event Ingestion API

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
