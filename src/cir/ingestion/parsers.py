"""Log parsers for various security data formats."""
import json
import re
from datetime import datetime
from typing import Dict, Any, Optional, List
from abc import ABC, abstractmethod
from ..core.models import Alert, AlertSource, SeverityLevel, AlertStatus
import uuid


class BaseParser(ABC):
    """Base class for log parsers."""
    
    @abstractmethod
    def parse(self, raw_log: str) -> Optional[Alert]:
        """Parse raw log into Alert object."""
        pass
    
    def generate_alert_id(self) -> str:
        """Generate unique alert ID."""
        return f"alert-{uuid.uuid4().hex[:12]}"
    
    def parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse timestamp string to datetime."""
        # Try common formats
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%d/%b/%Y:%H:%M:%S %z",
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue
        
        # Default to current time if parsing fails
        return datetime.utcnow()


class SIEMParser(BaseParser):
    """Parser for SIEM logs (generic JSON format)."""
    
    def parse(self, raw_log: str) -> Optional[Alert]:
        """Parse SIEM JSON log."""
        try:
            data = json.loads(raw_log) if isinstance(raw_log, str) else raw_log
            
            return Alert(
                id=data.get('id', self.generate_alert_id()),
                timestamp=self.parse_timestamp(data.get('timestamp', data.get('time', ''))),
                source=AlertSource.SIEM,
                severity=SeverityLevel(data.get('severity', 'medium').lower()),
                status=AlertStatus.NEW,
                title=data.get('title', data.get('rule_name', 'Unknown Alert')),
                description=data.get('description', data.get('message', '')),
                raw_data=data,
                source_ip=data.get('source_ip', data.get('src_ip')),
                dest_ip=data.get('dest_ip', data.get('dst_ip')),
                source_port=data.get('source_port', data.get('src_port')),
                dest_port=data.get('dest_port', data.get('dst_port')),
                user=data.get('user', data.get('username')),
                hostname=data.get('hostname', data.get('host')),
                attack_type=data.get('attack_type', data.get('category')),
                mitre_tactics=data.get('mitre_tactics', []),
                mitre_techniques=data.get('mitre_techniques', []),
            )
        except Exception as e:
            print(f"Error parsing SIEM log: {e}")
            return None


class EDRParser(BaseParser):
    """Parser for EDR (Endpoint Detection and Response) logs."""
    
    def parse(self, raw_log: str) -> Optional[Alert]:
        """Parse EDR log."""
        try:
            data = json.loads(raw_log) if isinstance(raw_log, str) else raw_log
            
            # Determine severity based on threat level
            threat_level = data.get('threat_level', 'medium').lower()
            severity_map = {
                'critical': SeverityLevel.CRITICAL,
                'high': SeverityLevel.HIGH,
                'medium': SeverityLevel.MEDIUM,
                'low': SeverityLevel.LOW,
            }
            severity = severity_map.get(threat_level, SeverityLevel.MEDIUM)
            
            return Alert(
                id=data.get('event_id', self.generate_alert_id()),
                timestamp=self.parse_timestamp(data.get('timestamp', data.get('event_time', ''))),
                source=AlertSource.EDR,
                severity=severity,
                status=AlertStatus.NEW,
                title=data.get('event_type', 'EDR Alert'),
                description=data.get('description', data.get('event_description', '')),
                raw_data=data,
                source_ip=data.get('ip_address'),
                user=data.get('user', data.get('username')),
                hostname=data.get('hostname', data.get('computer_name')),
                process=data.get('process_name', data.get('process')),
                attack_type=data.get('attack_type', data.get('tactic')),
                mitre_tactics=data.get('mitre_tactics', []),
                mitre_techniques=data.get('mitre_techniques', []),
            )
        except Exception as e:
            print(f"Error parsing EDR log: {e}")
            return None


class FirewallParser(BaseParser):
    """Parser for firewall logs."""
    
    def parse(self, raw_log: str) -> Optional[Alert]:
        """Parse firewall log."""
        try:
            # Try JSON first
            if raw_log.strip().startswith('{'):
                data = json.loads(raw_log)
            else:
                # Parse common syslog format
                data = self._parse_syslog(raw_log)
            
            # Only create alerts for denied/blocked traffic
            action = data.get('action', '').lower()
            if action not in ['deny', 'denied', 'block', 'blocked', 'drop', 'dropped']:
                return None
            
            severity = SeverityLevel.MEDIUM
            if data.get('threat_detected'):
                severity = SeverityLevel.HIGH
            
            return Alert(
                id=self.generate_alert_id(),
                timestamp=self.parse_timestamp(data.get('timestamp', '')),
                source=AlertSource.FIREWALL,
                severity=severity,
                status=AlertStatus.NEW,
                title=f"Firewall: {action.title()} Connection",
                description=f"Connection blocked from {data.get('source_ip')} to {data.get('dest_ip')}:{data.get('dest_port')}",
                raw_data=data,
                source_ip=data.get('source_ip'),
                dest_ip=data.get('dest_ip'),
                source_port=data.get('source_port'),
                dest_port=data.get('dest_port'),
                attack_type='network',
            )
        except Exception as e:
            print(f"Error parsing firewall log: {e}")
            return None
    
    def _parse_syslog(self, log: str) -> Dict[str, Any]:
        """Parse syslog format firewall log."""
        # Simple regex-based parsing
        data = {}
        
        # Extract timestamp (simplified)
        timestamp_match = re.search(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', log)
        if timestamp_match:
            data['timestamp'] = timestamp_match.group(1)
        
        # Extract IPs and ports
        ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        ips = re.findall(ip_pattern, log)
        if len(ips) >= 2:
            data['source_ip'] = ips[0]
            data['dest_ip'] = ips[1]
        
        # Extract action
        action_match = re.search(r'(DENY|DENIED|BLOCK|BLOCKED|DROP|DROPPED|ACCEPT|ALLOWED)', log, re.IGNORECASE)
        if action_match:
            data['action'] = action_match.group(1)
        
        return data


class IDSParser(BaseParser):
    """Parser for IDS/IPS logs (Snort/Suricata format)."""
    
    def parse(self, raw_log: str) -> Optional[Alert]:
        """Parse IDS log."""
        try:
            data = json.loads(raw_log) if isinstance(raw_log, str) else raw_log
            
            # IDS alerts are typically medium to high severity
            priority = data.get('priority', 2)
            severity_map = {1: SeverityLevel.CRITICAL, 2: SeverityLevel.HIGH, 3: SeverityLevel.MEDIUM}
            severity = severity_map.get(priority, SeverityLevel.MEDIUM)
            
            return Alert(
                id=data.get('alert_id', self.generate_alert_id()),
                timestamp=self.parse_timestamp(data.get('timestamp', '')),
                source=AlertSource.IDS,
                severity=severity,
                status=AlertStatus.NEW,
                title=data.get('signature', data.get('alert', 'IDS Alert')),
                description=data.get('description', data.get('message', '')),
                raw_data=data,
                source_ip=data.get('src_ip', data.get('source_ip')),
                dest_ip=data.get('dest_ip', data.get('dst_ip')),
                source_port=data.get('src_port', data.get('source_port')),
                dest_port=data.get('dest_port', data.get('dst_port')),
                attack_type=data.get('category', data.get('classification')),
            )
        except Exception as e:
            print(f"Error parsing IDS log: {e}")
            return None


class LogIngestionEngine:
    """Main engine for ingesting and parsing security logs."""
    
    def __init__(self):
        self.parsers = {
            'siem': SIEMParser(),
            'edr': EDRParser(),
            'firewall': FirewallParser(),
            'ids': IDSParser(),
        }
    
    def ingest(self, raw_log: str, source_type: str = 'siem') -> Optional[Alert]:
        """Ingest and parse a raw log."""
        parser = self.parsers.get(source_type.lower())
        if not parser:
            print(f"Unknown source type: {source_type}")
            return None
        
        return parser.parse(raw_log)
    
    def ingest_batch(self, raw_logs: List[str], source_type: str = 'siem') -> List[Alert]:
        """Ingest a batch of logs."""
        alerts = []
        for raw_log in raw_logs:
            alert = self.ingest(raw_log, source_type)
            if alert:
                alerts.append(alert)
        return alerts
