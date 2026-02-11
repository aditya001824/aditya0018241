"""Anomaly detection engine using PyOD and tsfresh."""
from typing import List, Dict, Any, Optional
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from pyod.models.iforest import IForest
from pyod.models.lof import LOF
from pyod.models.copod import COPOD
from sklearn.preprocessing import StandardScaler
from ..core.models import Alert, AnomalyDetectionResult
from ..core.config import config_manager


class FeatureExtractor:
    """Extract features from alerts for anomaly detection."""
    
    def __init__(self):
        self.scaler = StandardScaler()
    
    def extract_features(self, alerts: List[Alert]) -> np.ndarray:
        """Extract numerical features from alerts."""
        features = []
        
        for alert in alerts:
            feature_vector = [
                # Severity (encoded)
                self._encode_severity(alert.severity.value),
                # Source (encoded)
                self._encode_source(alert.source.value),
                # Time-based features
                alert.timestamp.hour,
                alert.timestamp.weekday(),
                # Port features (if available)
                alert.source_port or 0,
                alert.dest_port or 0,
                # String length features
                len(alert.title),
                len(alert.description),
                # MITRE ATT&CK coverage
                len(alert.mitre_tactics),
                len(alert.mitre_techniques),
            ]
            features.append(feature_vector)
        
        return np.array(features)
    
    def _encode_severity(self, severity: str) -> int:
        """Encode severity to numerical value."""
        severity_map = {
            'info': 1,
            'low': 2,
            'medium': 3,
            'high': 4,
            'critical': 5
        }
        return severity_map.get(severity, 3)
    
    def _encode_source(self, source: str) -> int:
        """Encode alert source to numerical value."""
        source_map = {
            'siem': 1,
            'edr': 2,
            'firewall': 3,
            'ids': 4,
            'proxy': 5,
            'authentication': 6,
            'custom': 7
        }
        return source_map.get(source, 1)


class UEBAEngine:
    """User and Entity Behavior Analytics engine."""
    
    def __init__(self, baseline_days: int = 30):
        self.baseline_days = baseline_days
        self.user_baselines: Dict[str, Dict[str, Any]] = {}
        self.entity_baselines: Dict[str, Dict[str, Any]] = {}
    
    def build_baseline(self, alerts: List[Alert]) -> None:
        """Build behavioral baselines for users and entities."""
        # Group alerts by user
        user_alerts = {}
        entity_alerts = {}
        
        for alert in alerts:
            if alert.user:
                if alert.user not in user_alerts:
                    user_alerts[alert.user] = []
                user_alerts[alert.user].append(alert)
            
            if alert.hostname:
                if alert.hostname not in entity_alerts:
                    entity_alerts[alert.hostname] = []
                entity_alerts[alert.hostname].append(alert)
        
        # Calculate baselines
        for user, user_alert_list in user_alerts.items():
            self.user_baselines[user] = self._calculate_baseline(user_alert_list)
        
        for entity, entity_alert_list in entity_alerts.items():
            self.entity_baselines[entity] = self._calculate_baseline(entity_alert_list)
    
    def _calculate_baseline(self, alerts: List[Alert]) -> Dict[str, Any]:
        """Calculate baseline metrics from alerts."""
        if not alerts:
            return {}
        
        df = pd.DataFrame([{
            'timestamp': a.timestamp,
            'severity': a.severity.value,
            'hour': a.timestamp.hour,
            'source': a.source.value,
        } for a in alerts])
        
        return {
            'avg_alerts_per_day': len(alerts) / max(1, (alerts[-1].timestamp - alerts[0].timestamp).days or 1),
            'common_hours': df['hour'].mode().tolist(),
            'common_sources': df['source'].mode().tolist(),
            'severity_distribution': df['severity'].value_counts().to_dict(),
        }
    
    def detect_anomaly(self, alert: Alert) -> float:
        """Detect if an alert represents anomalous behavior."""
        score = 0.0
        
        # Check user behavior
        if alert.user and alert.user in self.user_baselines:
            baseline = self.user_baselines[alert.user]
            
            # Unusual hour
            if alert.timestamp.hour not in baseline.get('common_hours', []):
                score += 0.3
            
            # Unusual source
            if alert.source.value not in baseline.get('common_sources', []):
                score += 0.2
            
            # Higher severity than usual
            severity_dist = baseline.get('severity_distribution', {})
            if alert.severity.value not in severity_dist:
                score += 0.3
        
        # Check entity behavior
        if alert.hostname and alert.hostname in self.entity_baselines:
            baseline = self.entity_baselines[alert.hostname]
            
            # Similar checks for entity
            if alert.timestamp.hour not in baseline.get('common_hours', []):
                score += 0.2
        
        return min(score, 1.0)


class AnomalyDetectionEngine:
    """Multi-algorithm anomaly detection engine."""
    
    def __init__(self):
        self.config = config_manager.get_detection_config()
        self.feature_extractor = FeatureExtractor()
        self.ueba_engine = UEBAEngine(baseline_days=30)
        
        # Initialize detectors
        contamination = config_manager.settings.anomaly_contamination
        self.detectors = {
            'IsolationForest': IForest(contamination=contamination, random_state=42),
            'LOF': LOF(n_neighbors=20, contamination=contamination),
            'COPOD': COPOD(contamination=contamination),
        }
        
        self.is_trained = False
        self.scaler = StandardScaler()
    
    def train(self, alerts: List[Alert]) -> None:
        """Train anomaly detection models on historical alerts."""
        if len(alerts) < 10:
            print("Warning: Not enough alerts for training (minimum 10 required)")
            return
        
        # Extract features
        features = self.feature_extractor.extract_features(alerts)
        
        # Normalize features
        features_scaled = self.scaler.fit_transform(features)
        
        # Train each detector
        for name, detector in self.detectors.items():
            try:
                detector.fit(features_scaled)
                print(f"Trained {name} on {len(alerts)} alerts")
            except Exception as e:
                print(f"Error training {name}: {e}")
        
        # Build UEBA baselines
        self.ueba_engine.build_baseline(alerts)
        
        self.is_trained = True
    
    def detect(self, alert: Alert) -> AnomalyDetectionResult:
        """Detect if an alert is anomalous."""
        if not self.is_trained:
            # Return default result if not trained
            return AnomalyDetectionResult(
                alert_id=alert.id,
                is_anomaly=False,
                anomaly_score=0.5,
                algorithms_used=[],
                feature_contributions={}
            )
        
        # Extract features for single alert
        features = self.feature_extractor.extract_features([alert])
        features_scaled = self.scaler.transform(features)
        
        # Get predictions from all detectors
        scores = []
        algorithms_used = []
        
        for name, detector in self.detectors.items():
            try:
                # Get outlier score (higher = more anomalous)
                score = detector.decision_function(features_scaled)[0]
                # Normalize to 0-1 range
                normalized_score = 1 / (1 + np.exp(-score))  # Sigmoid
                scores.append(normalized_score)
                algorithms_used.append(name)
            except Exception as e:
                print(f"Error in {name} detection: {e}")
        
        # Add UEBA score
        ueba_score = self.ueba_engine.detect_anomaly(alert)
        scores.append(ueba_score)
        algorithms_used.append('UEBA')
        
        # Calculate ensemble score (average)
        ensemble_score = np.mean(scores) if scores else 0.5
        
        # Determine if anomalous based on threshold
        threshold = config_manager.settings.anomaly_threshold
        is_anomaly = ensemble_score >= threshold
        
        return AnomalyDetectionResult(
            alert_id=alert.id,
            is_anomaly=is_anomaly,
            anomaly_score=float(ensemble_score),
            algorithms_used=algorithms_used,
            feature_contributions={
                'ensemble': float(ensemble_score),
                'ueba': float(ueba_score),
            }
        )
    
    def detect_batch(self, alerts: List[Alert]) -> List[AnomalyDetectionResult]:
        """Detect anomalies in a batch of alerts."""
        return [self.detect(alert) for alert in alerts]
