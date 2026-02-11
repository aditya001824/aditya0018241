# API Documentation

## Overview

The Cyber Incident Response System provides a RESTful API for managing security alerts, incidents, and response playbooks.

Base URL: `http://localhost:8000`

## Endpoints

### Health & Status

#### GET /
Get service information

#### GET /health
Health check endpoint

#### GET /api/v1/stats
Get system statistics

### Alert Management

#### POST /api/v1/alerts/ingest
Ingest a single security alert

**Parameters:**
- `source_type` (query): Type of source (siem, edr, firewall, ids)

#### POST /api/v1/alerts/ingest/batch
Ingest multiple alerts

#### GET /api/v1/alerts
List all alerts with optional filtering

#### GET /api/v1/alerts/{alert_id}
Get a specific alert by ID

### Detection

#### POST /api/v1/detection/train
Train the anomaly detection engine

### Correlation

#### POST /api/v1/correlation/run
Run correlation engine

#### GET /api/v1/incidents
List incidents

#### GET /api/v1/incidents/{incident_id}
Get specific incident

### Playbooks

#### POST /api/v1/incidents/{incident_id}/playbook
Generate playbook for incident

#### GET /api/v1/playbooks
List playbooks

#### GET /api/v1/playbooks/{playbook_id}
Get specific playbook

## Interactive Documentation

- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`
