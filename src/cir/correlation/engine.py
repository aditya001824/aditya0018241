"""Alert correlation engine for incident grouping."""
from typing import List, Dict, Set, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
import uuid
from ..core.models import Alert, Incident, SeverityLevel, AlertStatus, CorrelationResult
from ..core.config import config_manager


class CorrelationEngine:
    """Correlates alerts into incidents based on similarity and temporal proximity."""
    
    def __init__(self):
        self.config = config_manager.get_correlation_config()
        self.time_window = config_manager.settings.correlation_time_window
        self.min_score = config_manager.settings.correlation_min_score
        self.incidents: Dict[str, Incident] = {}
        self.alert_to_incident: Dict[str, str] = {}
    
    def correlate_alerts(self, alerts: List[Alert]) -> List[Incident]:
        """Correlate a list of alerts into incidents."""
        if not alerts:
            return []
        
        # Sort alerts by timestamp
        sorted_alerts = sorted(alerts, key=lambda a: a.timestamp)
        
        # Group alerts within time windows
        time_groups = self._group_by_time_window(sorted_alerts)
        
        # Correlate within each time group
        new_incidents = []
        for group in time_groups:
            incidents = self._correlate_group(group)
            new_incidents.extend(incidents)
        
        return new_incidents
    
    def _group_by_time_window(self, alerts: List[Alert]) -> List[List[Alert]]:
        """Group alerts into time windows."""
        if not alerts:
            return []
        
        groups = []
        current_group = [alerts[0]]
        window_start = alerts[0].timestamp
        
        for alert in alerts[1:]:
            time_diff = (alert.timestamp - window_start).total_seconds()
            
            if time_diff <= self.time_window:
                current_group.append(alert)
            else:
                groups.append(current_group)
                current_group = [alert]
                window_start = alert.timestamp
        
        if current_group:
            groups.append(current_group)
        
        return groups
    
    def _correlate_group(self, alerts: List[Alert]) -> List[Incident]:
        """Correlate alerts within a time window."""
        incidents = []
        processed_alerts = set()
        
        for i, alert1 in enumerate(alerts):
            if alert1.id in processed_alerts:
                continue
            
            # Start a new incident cluster
            cluster = [alert1]
            processed_alerts.add(alert1.id)
            
            # Find related alerts
            for alert2 in alerts[i+1:]:
                if alert2.id in processed_alerts:
                    continue
                
                score, factors = self._calculate_correlation_score(alert1, alert2)
                
                if score >= self.min_score:
                    cluster.append(alert2)
                    processed_alerts.add(alert2.id)
            
            # Create incident if we have correlated alerts
            if len(cluster) >= 1:
                incident = self._create_incident(cluster)
                incidents.append(incident)
                
                # Track mapping
                for alert in cluster:
                    self.alert_to_incident[alert.id] = incident.id
                    alert.incident_id = incident.id
        
        return incidents
    
    def _calculate_correlation_score(self, alert1: Alert, alert2: Alert) -> Tuple[float, List[str]]:
        """Calculate correlation score between two alerts."""
        score = 0.0
        factors = []
        
        # Get correlation rules from config
        rules = self.config.get('grouping_rules', [])
        
        for rule in rules:
            field = rule.get('field')
            weight = rule.get('weight', 0.5)
            
            # Check if both alerts have the field and values match
            val1 = getattr(alert1, field, None)
            val2 = getattr(alert2, field, None)
            
            if val1 and val2 and val1 == val2:
                score += weight
                factors.append(rule.get('name', field))
        
        # Time proximity (closer in time = higher score)
        time_diff = abs((alert2.timestamp - alert1.timestamp).total_seconds())
        time_score = max(0, 1 - (time_diff / self.time_window)) * 0.3
        score += time_score
        
        if time_score > 0.2:
            factors.append("Temporal Proximity")
        
        # Same severity
        if alert1.severity == alert2.severity:
            score += 0.2
            factors.append("Same Severity")
        
        # MITRE technique overlap
        if alert1.mitre_techniques and alert2.mitre_techniques:
            overlap = set(alert1.mitre_techniques) & set(alert2.mitre_techniques)
            if overlap:
                score += 0.3
                factors.append("MITRE Technique Overlap")
        
        # Normalize score to 0-1 range
        max_possible_score = sum(r.get('weight', 0.5) for r in rules) + 0.8
        normalized_score = min(score / max_possible_score, 1.0) if max_possible_score > 0 else 0.0
        
        return normalized_score, factors
    
    def _create_incident(self, alerts: List[Alert]) -> Incident:
        """Create an incident from correlated alerts."""
        incident_id = f"incident-{uuid.uuid4().hex[:12]}"
        
        # Determine incident severity (highest among alerts)
        severity_order = [
            SeverityLevel.CRITICAL,
            SeverityLevel.HIGH,
            SeverityLevel.MEDIUM,
            SeverityLevel.LOW,
            SeverityLevel.INFO
        ]
        
        incident_severity = SeverityLevel.INFO
        for sev in severity_order:
            if any(a.severity == sev for a in alerts):
                incident_severity = sev
                break
        
        # Collect affected systems and users
        affected_systems = list(set(a.hostname for a in alerts if a.hostname))
        affected_users = list(set(a.user for a in alerts if a.user))
        
        # Build attack timeline
        attack_timeline = [
            {
                'timestamp': alert.timestamp.isoformat(),
                'alert_id': alert.id,
                'title': alert.title,
                'severity': alert.severity.value,
            }
            for alert in sorted(alerts, key=lambda a: a.timestamp)
        ]
        
        # Calculate correlation factors
        correlation_factors = []
        if len(set(a.source_ip for a in alerts if a.source_ip)) == 1:
            correlation_factors.append("Same Source IP")
        if len(set(a.user for a in alerts if a.user)) == 1:
            correlation_factors.append("Same User")
        if len(set(a.hostname for a in alerts if a.hostname)) == 1:
            correlation_factors.append("Same Host")
        
        # Generate incident title
        if len(alerts) == 1:
            title = alerts[0].title
        else:
            common_attack = self._find_common_attack_type(alerts)
            title = f"Multi-Stage Attack: {common_attack}" if common_attack else "Correlated Security Incident"
        
        # Generate description
        description = f"Incident involving {len(alerts)} correlated alert(s)"
        if affected_users:
            description += f" affecting user(s): {', '.join(affected_users[:3])}"
        if affected_systems:
            description += f" on system(s): {', '.join(affected_systems[:3])}"
        
        incident = Incident(
            id=incident_id,
            created_at=min(a.timestamp for a in alerts),
            updated_at=datetime.utcnow(),
            severity=incident_severity,
            status=AlertStatus.NEW,
            title=title,
            description=description,
            alert_ids=[a.id for a in alerts],
            alert_count=len(alerts),
            correlation_score=0.8,  # Average correlation score
            correlation_factors=correlation_factors,
            affected_systems=affected_systems,
            affected_users=affected_users,
            attack_timeline=attack_timeline,
        )
        
        self.incidents[incident_id] = incident
        return incident
    
    def _find_common_attack_type(self, alerts: List[Alert]) -> Optional[str]:
        """Find the most common attack type among alerts."""
        attack_types = [a.attack_type for a in alerts if a.attack_type]
        if not attack_types:
            return None
        
        # Return most common
        from collections import Counter
        counter = Counter(attack_types)
        return counter.most_common(1)[0][0] if counter else None
    
    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Get an incident by ID."""
        return self.incidents.get(incident_id)
    
    def get_incidents_for_alert(self, alert_id: str) -> Optional[str]:
        """Get the incident ID for an alert."""
        return self.alert_to_incident.get(alert_id)
    
    def get_all_incidents(self) -> List[Incident]:
        """Get all incidents."""
        return list(self.incidents.values())
