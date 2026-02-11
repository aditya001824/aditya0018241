# Installation & Usage Guide

## Prerequisites

- Python 3.9 or higher
- pip package manager
- (Optional) Ollama for LLM-based playbook generation

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/aditya001824/aditya001824.git
cd aditya001824
```

### 2. Create Virtual Environment (Recommended)

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Install Package

```bash
pip install -e .
```

### 5. Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit .env file with your settings (optional)
vim .env
```

## Quick Start

### Run the Demo

The easiest way to see the system in action:

```bash
python examples/demo.py
```

This will:
1. Initialize all engines
2. Ingest sample security logs
3. Train anomaly detection models
4. Detect anomalies in alerts
5. Correlate alerts into incidents
6. Generate response playbooks

### Start the API Server

```bash
# Using the installed command
cir-server

# Or using Python directly
python -m uvicorn cir.api.server:app --host 0.0.0.0 --port 8000 --reload
```

Access the API at: `http://localhost:8000`
Interactive docs: `http://localhost:8000/docs`

## Basic Usage

### Programmatic Usage

```python
from cir.ingestion.parsers import LogIngestionEngine
from cir.detection.anomaly import AnomalyDetectionEngine
from cir.correlation.engine import CorrelationEngine
from cir.playbook.generator import PlaybookGenerator

# Initialize engines
ingestion = LogIngestionEngine()
detector = AnomalyDetectionEngine()
correlator = CorrelationEngine()
playbook_gen = PlaybookGenerator()

# Parse a SIEM log
alert = ingestion.ingest(raw_log_data, source_type='siem')

# Train detector (requires multiple alerts)
detector.train(alert_list)

# Detect anomalies
result = detector.detect(alert)
print(f"Anomaly Score: {result.anomaly_score}")

# Correlate alerts into incidents
incidents = correlator.correlate_alerts(alert_list)

# Generate playbook
for incident in incidents:
    playbook = playbook_gen.generate_playbook(incident)
    print(f"Playbook: {playbook.title}")
    for step in playbook.steps:
        print(f"  {step.step_number}. {step.title}")
```

### API Usage

#### Ingest Alerts

```bash
curl -X POST "http://localhost:8000/api/v1/alerts/ingest?source_type=siem" \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2024-02-11T10:30:00Z",
    "severity": "high",
    "title": "Suspicious Activity",
    "source_ip": "192.168.1.100",
    "user": "admin"
  }'
```

#### Train Anomaly Detector

```bash
curl -X POST "http://localhost:8000/api/v1/detection/train"
```

#### Run Correlation

```bash
curl -X POST "http://localhost:8000/api/v1/correlation/run"
```

#### Generate Playbook

```bash
curl -X POST "http://localhost:8000/api/v1/incidents/{incident_id}/playbook"
```

## Configuration

### Environment Variables (.env)

```bash
# API Settings
API_HOST=0.0.0.0
API_PORT=8000

# Ollama Settings (for LLM-based playbooks)
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama2

# Detection Settings
ANOMALY_THRESHOLD=0.75
CORRELATION_TIME_WINDOW=300
```

### YAML Configuration (config/config.yaml)

```yaml
detection:
  algorithms:
    - name: "IsolationForest"
      enabled: true
      params:
        contamination: 0.1

correlation:
  time_window_seconds: 300
  min_correlation_score: 0.6

playbook:
  llm:
    provider: "ollama"
    model: "llama2"
    temperature: 0.3
```

## Optional: Install Ollama

For LLM-based playbook generation:

1. Install Ollama: https://ollama.ai/
2. Pull a model:
   ```bash
   ollama pull llama2
   ```
3. Start Ollama service:
   ```bash
   ollama serve
   ```

The system will automatically fall back to template-based playbooks if Ollama is unavailable.

## Troubleshooting

### Dependencies Not Installing

```bash
# Upgrade pip
pip install --upgrade pip

# Install with verbose output
pip install -r requirements.txt -v
```

### Import Errors

```bash
# Ensure package is installed
pip install -e .

# Add to PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
```

### Ollama Connection Issues

- Check Ollama is running: `ollama list`
- Verify OLLAMA_HOST in .env matches Ollama URL
- System will use template-based fallback if Ollama unavailable

## Testing

Run basic structure tests:

```bash
python tests/test_basic.py
```

Run demo with sample data:

```bash
python examples/demo.py
```

## Next Steps

- Customize correlation rules in `config/config.yaml`
- Add your own log parsers for custom formats
- Integrate with Elasticsearch for persistent storage
- Build a UI dashboard for visualization
- Set up automated alert ingestion from SIEM

## Support

For issues or questions, please open an issue on GitHub.
