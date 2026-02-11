# Architecture Documentation

## System Overview

The Cyber Incident Response (CIR) System is a modular, AI-powered platform for automated security incident response.

## Core Components

### 1. Ingestion Engine
- Multi-format log parsing (SIEM, EDR, Firewall, IDS)
- Normalization and validation
- MITRE ATT&CK mapping

### 2. Anomaly Detection Engine
- PyOD-based multi-algorithm detection
- UEBA (User and Entity Behavior Analytics)
- Ensemble scoring

### 3. Correlation Engine
- Temporal correlation
- Entity-based grouping
- Attack chain detection

### 4. Playbook Generator
- LLM-based generation (Ollama)
- Template-based fallback
- NIST SP 800-61 compliant

### 5. API Layer
- FastAPI REST endpoints
- Async processing
- OpenAPI documentation

## Data Flow

```
Raw Logs → Ingestion → Alerts → Anomaly Detection → Scored Alerts
                                        ↓
                                  Correlation
                                        ↓
                                   Incidents
                                        ↓
                              Playbook Generation
                                        ↓
                             Response Playbooks
```

## Security

- Fully local processing
- No external data transfer
- Local LLM inference
- Configurable security policies
