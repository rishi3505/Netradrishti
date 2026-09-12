# Module 4: Suspicious Activity Detection Engine

## Overview
The Suspicious Activity Detection Engine bridges the gap between raw normalized data (Module 3) and full incident correlation (Module 5). It analyzes `NormalizedEvent`s to generate `SecuritySignal`s when suspicious patterns are observed.

## Architecture
The engine is modular and explainable:
- **DetectionEngine**: The core that runs events through rules.
- **EventWindow**: Allows querying recent events from the database (e.g. last 5 minutes for a Source IP).
- **DetectionContext**: Provides the current event and historical context to rules.
- **Rules Framework**: A base class for all rules and a registry to manage them.

## Rules Implemented
- `AUTH-001`: Brute Force Authentication
- `AUTH-002`: Password Spraying
- `AUTH-003`: Suspicious Successful Login
- `NET-001`: Port Scanning
- `NET-002`: Network Connection Burst
- `NET-003`: Suspicious Outbound Connection
- `END-001`: Suspicious Process Execution
- `BEH-001`: Basic Behavioral Deviation

## Scoring
- **Confidence**: 0-100 score based on rule strength, threshold deviation, and number of affected entities.
- **Risk**: 0-100 score based on severity (70%) and confidence (30%).

## Signal Deduplication
Prevents duplicate signals by finding recent similar signals (same rule ID and overlapping entities) and updating them (incrementing occurrences and updating confidence) instead of creating a new signal.

## APIs
- `GET /api/v1/detection/rules`: List all rules
- `GET /api/v1/detection/rules/{rule_id}`: Get a rule
- `PATCH /api/v1/detection/rules/{rule_id}`: Update rule config
- `GET /api/v1/signals`: List signals
- `GET /api/v1/signals/{signal_id}`: Get a signal
