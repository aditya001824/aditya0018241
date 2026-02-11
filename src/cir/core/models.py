"""Core data models for the incident response system."""
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    """Alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, Enum):
    """Alert status."""
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    ESCALATED = "escalated"


class AlertSource(str, Enum):
    """Source of the alert."""
    SIEM = "siem"
    EDR = "edr"
    FIREWALL = "firewall"
    IDS = "ids"
    PROXY = "proxy"
    AUTH = "authentication"
    CUSTOM = "custom"


class Alert(BaseModel):
    """Security alert model."""
    id: str = Field(description="Unique alert identifier")
    timestamp: datetime = Field(description="Alert timestamp")
    source: AlertSource = Field(description="Alert source system")
    severity: SeverityLevel = Field(description="Alert severity")
    status: AlertStatus = Field(default=AlertStatus.NEW)
    
    # Alert details
    title: str = Field(description="Alert title")
    description: str = Field(description="Alert description")
    raw_data: Dict[str, Any] = Field(default_factory=dict, description="Raw alert data")
    
    # Context
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    user: Optional[str] = None
    hostname: Optional[str] = None
    process: Optional[str] = None
    
    # Detection metadata
    attack_type: Optional[str] = None
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    
    # Anomaly scores
    anomaly_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    fidelity_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    
    # Correlation
    incident_id: Optional[str] = None
    related_alerts: List[str] = Field(default_factory=list)
    
    class Config:
        json_schema_extra = {
            "example": {
                "id": "alert-12345",
                "timestamp": "2024-01-15T10:30:00Z",
                "source": "edr",
                "severity": "high",
                "status": "new",
                "title": "Suspicious PowerShell Execution",
                "description": "Detected encoded PowerShell command execution",
                "source_ip": "192.168.1.100",
                "user": "john.doe",
                "hostname": "WORKSTATION-01",
                "attack_type": "execution",
                "mitre_techniques": ["T1059.001"]
            }
        }


class Incident(BaseModel):
    """Security incident model (grouped alerts)."""
    id: str = Field(description="Unique incident identifier")
    created_at: datetime = Field(description="Incident creation time")
    updated_at: datetime = Field(description="Last update time")
    
    severity: SeverityLevel = Field(description="Incident severity")
    status: AlertStatus = Field(default=AlertStatus.NEW)
    
    title: str = Field(description="Incident title")
    description: str = Field(description="Incident description")
    
    # Related alerts
    alert_ids: List[str] = Field(default_factory=list)
    alert_count: int = Field(default=0)
    
    # Correlation details
    correlation_score: float = Field(ge=0.0, le=1.0)
    correlation_factors: List[str] = Field(default_factory=list)
    
    # Incident metadata
    affected_systems: List[str] = Field(default_factory=list)
    affected_users: List[str] = Field(default_factory=list)
    attack_timeline: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Playbook
    playbook_id: Optional[str] = None
    recommended_actions: List[str] = Field(default_factory=list)


class PlaybookStep(BaseModel):
    """Individual step in an incident response playbook."""
    step_number: int
    title: str
    description: str
    action_type: str  # investigate, contain, eradicate, recover
    commands: List[str] = Field(default_factory=list)
    expected_outcome: str
    approval_required: bool = False


class Playbook(BaseModel):
    """Incident response playbook."""
    id: str = Field(description="Unique playbook identifier")
    incident_id: str = Field(description="Related incident ID")
    created_at: datetime = Field(description="Playbook creation time")
    
    title: str = Field(description="Playbook title")
    description: str = Field(description="Playbook description")
    severity: SeverityLevel
    
    # Steps
    steps: List[PlaybookStep] = Field(default_factory=list)
    
    # Metadata
    estimated_duration: Optional[str] = None
    prerequisites: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    
    # Execution
    executed: bool = False
    execution_status: Optional[str] = None
    execution_log: List[Dict[str, Any]] = Field(default_factory=list)


class AnomalyDetectionResult(BaseModel):
    """Result from anomaly detection."""
    alert_id: str
    is_anomaly: bool
    anomaly_score: float = Field(ge=0.0, le=1.0)
    algorithms_used: List[str]
    feature_contributions: Dict[str, float] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class CorrelationResult(BaseModel):
    """Result from alert correlation."""
    incident_id: str
    alert_ids: List[str]
    correlation_score: float = Field(ge=0.0, le=1.0)
    correlation_factors: List[str]
    timestamp: datetime = Field(default_factory=datetime.utcnow)
