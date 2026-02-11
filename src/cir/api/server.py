"""FastAPI server for the Cyber Incident Response system."""
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional
from datetime import datetime
import uvicorn

from ..core.models import Alert, Incident, Playbook, SeverityLevel, AlertStatus
from ..core.config import settings
from ..ingestion.parsers import LogIngestionEngine
from ..detection.anomaly import AnomalyDetectionEngine
from ..correlation.engine import CorrelationEngine
from ..playbook.generator import PlaybookGenerator


# Initialize FastAPI app
app = FastAPI(
    title="Cyber Incident Response System",
    description="Autonomous AI-powered cyber incident response tool for banking",
    version="0.1.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize engines
ingestion_engine = LogIngestionEngine()
anomaly_engine = AnomalyDetectionEngine()
correlation_engine = CorrelationEngine()
playbook_generator = PlaybookGenerator()

# In-memory storage (in production, use Elasticsearch)
alerts_db: List[Alert] = []
incidents_db: List[Incident] = []
playbooks_db: List[Playbook] = []


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "Cyber Incident Response System",
        "version": "0.1.0",
        "status": "operational"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "anomaly_detector_trained": anomaly_engine.is_trained,
        "total_alerts": len(alerts_db),
        "total_incidents": len(incidents_db),
        "total_playbooks": len(playbooks_db)
    }


@app.post("/api/v1/alerts/ingest", response_model=Alert)
async def ingest_alert(
    raw_log: dict,
    source_type: str = "siem",
    background_tasks: BackgroundTasks = None
):
    """
    Ingest a security alert from various sources.
    
    Args:
        raw_log: Raw log data (JSON format)
        source_type: Type of source (siem, edr, firewall, ids)
    """
    # Parse the log
    alert = ingestion_engine.ingest(raw_log, source_type)
    
    if not alert:
        raise HTTPException(status_code=400, detail="Failed to parse log")
    
    # Store alert
    alerts_db.append(alert)
    
    # Run anomaly detection if trained
    if anomaly_engine.is_trained:
        detection_result = anomaly_engine.detect(alert)
        alert.anomaly_score = detection_result.anomaly_score
        alert.fidelity_score = 1.0 - detection_result.anomaly_score  # Inverse for fidelity
    
    # Schedule background correlation
    if background_tasks:
        background_tasks.add_task(correlate_recent_alerts)
    
    return alert


@app.post("/api/v1/alerts/ingest/batch", response_model=List[Alert])
async def ingest_alerts_batch(
    raw_logs: List[dict],
    source_type: str = "siem",
    background_tasks: BackgroundTasks = None
):
    """
    Ingest a batch of security alerts.
    
    Args:
        raw_logs: List of raw log data
        source_type: Type of source (siem, edr, firewall, ids)
    """
    alerts = ingestion_engine.ingest_batch(raw_logs, source_type)
    
    # Store alerts
    alerts_db.extend(alerts)
    
    # Run anomaly detection on batch
    if anomaly_engine.is_trained and alerts:
        detection_results = anomaly_engine.detect_batch(alerts)
        for alert, result in zip(alerts, detection_results):
            alert.anomaly_score = result.anomaly_score
            alert.fidelity_score = 1.0 - result.anomaly_score
    
    # Schedule background correlation
    if background_tasks:
        background_tasks.add_task(correlate_recent_alerts)
    
    return alerts


@app.get("/api/v1/alerts", response_model=List[Alert])
async def get_alerts(
    severity: Optional[SeverityLevel] = None,
    status: Optional[AlertStatus] = None,
    limit: int = 100,
    offset: int = 0
):
    """Get alerts with optional filtering."""
    filtered_alerts = alerts_db
    
    if severity:
        filtered_alerts = [a for a in filtered_alerts if a.severity == severity]
    
    if status:
        filtered_alerts = [a for a in filtered_alerts if a.status == status]
    
    # Apply pagination
    return filtered_alerts[offset:offset + limit]


@app.get("/api/v1/alerts/{alert_id}", response_model=Alert)
async def get_alert(alert_id: str):
    """Get a specific alert by ID."""
    for alert in alerts_db:
        if alert.id == alert_id:
            return alert
    
    raise HTTPException(status_code=404, detail="Alert not found")


@app.post("/api/v1/detection/train")
async def train_anomaly_detector():
    """Train the anomaly detection engine on existing alerts."""
    if len(alerts_db) < 10:
        raise HTTPException(
            status_code=400,
            detail="Not enough alerts for training (minimum 10 required)"
        )
    
    anomaly_engine.train(alerts_db)
    
    return {
        "status": "trained",
        "alerts_used": len(alerts_db),
        "message": "Anomaly detection engine trained successfully"
    }


@app.post("/api/v1/correlation/run")
async def run_correlation():
    """Manually trigger correlation on all alerts."""
    incidents = correlation_engine.correlate_alerts(alerts_db)
    
    # Store new incidents
    for incident in incidents:
        if incident.id not in [i.id for i in incidents_db]:
            incidents_db.append(incident)
    
    return {
        "status": "completed",
        "incidents_created": len(incidents),
        "total_incidents": len(incidents_db)
    }


@app.get("/api/v1/incidents", response_model=List[Incident])
async def get_incidents(
    severity: Optional[SeverityLevel] = None,
    status: Optional[AlertStatus] = None,
    limit: int = 100,
    offset: int = 0
):
    """Get incidents with optional filtering."""
    filtered_incidents = incidents_db
    
    if severity:
        filtered_incidents = [i for i in filtered_incidents if i.severity == severity]
    
    if status:
        filtered_incidents = [i for i in filtered_incidents if i.status == status]
    
    return filtered_incidents[offset:offset + limit]


@app.get("/api/v1/incidents/{incident_id}", response_model=Incident)
async def get_incident(incident_id: str):
    """Get a specific incident by ID."""
    for incident in incidents_db:
        if incident.id == incident_id:
            return incident
    
    raise HTTPException(status_code=404, detail="Incident not found")


@app.post("/api/v1/incidents/{incident_id}/playbook", response_model=Playbook)
async def generate_playbook_for_incident(incident_id: str):
    """Generate an incident response playbook for an incident."""
    # Find the incident
    incident = None
    for inc in incidents_db:
        if inc.id == incident_id:
            incident = inc
            break
    
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Generate playbook
    playbook = playbook_generator.generate_playbook(incident)
    
    # Store playbook
    playbooks_db.append(playbook)
    
    # Update incident with playbook reference
    incident.playbook_id = playbook.id
    incident.recommended_actions = [step.title for step in playbook.steps]
    
    return playbook


@app.get("/api/v1/playbooks", response_model=List[Playbook])
async def get_playbooks(limit: int = 100, offset: int = 0):
    """Get all playbooks."""
    return playbooks_db[offset:offset + limit]


@app.get("/api/v1/playbooks/{playbook_id}", response_model=Playbook)
async def get_playbook(playbook_id: str):
    """Get a specific playbook by ID."""
    for playbook in playbooks_db:
        if playbook.id == playbook_id:
            return playbook
    
    raise HTTPException(status_code=404, detail="Playbook not found")


@app.get("/api/v1/stats")
async def get_statistics():
    """Get system statistics."""
    # Calculate severity distribution
    severity_dist = {}
    for alert in alerts_db:
        sev = alert.severity.value
        severity_dist[sev] = severity_dist.get(sev, 0) + 1
    
    # Calculate source distribution
    source_dist = {}
    for alert in alerts_db:
        src = alert.source.value
        source_dist[src] = source_dist.get(src, 0) + 1
    
    return {
        "total_alerts": len(alerts_db),
        "total_incidents": len(incidents_db),
        "total_playbooks": len(playbooks_db),
        "severity_distribution": severity_dist,
        "source_distribution": source_dist,
        "anomaly_detector_trained": anomaly_engine.is_trained,
        "timestamp": datetime.utcnow().isoformat()
    }


async def correlate_recent_alerts():
    """Background task to correlate recent alerts."""
    # Get recent alerts (last hour)
    recent_alerts = [a for a in alerts_db[-100:]]
    
    if recent_alerts:
        incidents = correlation_engine.correlate_alerts(recent_alerts)
        
        # Store new incidents
        for incident in incidents:
            if incident.id not in [i.id for i in incidents_db]:
                incidents_db.append(incident)


def main():
    """Run the server."""
    uvicorn.run(
        "cir.api.server:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=True,
        log_level=settings.log_level.lower()
    )


if __name__ == "__main__":
    main()
