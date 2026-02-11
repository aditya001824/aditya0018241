"""Sample security logs for testing the system."""

# Sample SIEM logs
SAMPLE_SIEM_LOGS = [
    {
        "id": "siem-001",
        "timestamp": "2024-02-11T10:30:00Z",
        "severity": "high",
        "title": "Multiple Failed Login Attempts",
        "description": "User account lockout after 5 failed login attempts",
        "source_ip": "192.168.1.100",
        "user": "admin",
        "hostname": "DC-01",
        "attack_type": "credential_access",
        "mitre_techniques": ["T1110"]
    },
    {
        "id": "siem-002",
        "timestamp": "2024-02-11T10:35:00Z",
        "severity": "critical",
        "title": "Successful Login After Failed Attempts",
        "description": "User successfully authenticated after multiple failures",
        "source_ip": "192.168.1.100",
        "user": "admin",
        "hostname": "DC-01",
        "attack_type": "credential_access",
        "mitre_techniques": ["T1078"]
    },
    {
        "id": "siem-003",
        "timestamp": "2024-02-11T10:40:00Z",
        "severity": "high",
        "title": "Unusual Data Access Pattern",
        "description": "Large volume of database queries from admin account",
        "source_ip": "192.168.1.100",
        "user": "admin",
        "hostname": "DB-01",
        "attack_type": "collection",
        "mitre_techniques": ["T1005"]
    }
]

# Sample EDR logs
SAMPLE_EDR_LOGS = [
    {
        "event_id": "edr-001",
        "timestamp": "2024-02-11T11:00:00Z",
        "threat_level": "high",
        "event_type": "Suspicious PowerShell Execution",
        "description": "Encoded PowerShell command detected",
        "ip_address": "192.168.1.50",
        "user": "john.doe",
        "hostname": "WORKSTATION-01",
        "process_name": "powershell.exe",
        "attack_type": "execution",
        "mitre_techniques": ["T1059.001"]
    },
    {
        "event_id": "edr-002",
        "timestamp": "2024-02-11T11:05:00Z",
        "threat_level": "critical",
        "event_type": "Ransomware Behavior Detected",
        "description": "Mass file encryption activity detected",
        "ip_address": "192.168.1.50",
        "user": "john.doe",
        "hostname": "WORKSTATION-01",
        "process_name": "unknown.exe",
        "attack_type": "impact",
        "mitre_techniques": ["T1486"]
    },
    {
        "event_id": "edr-003",
        "timestamp": "2024-02-11T11:10:00Z",
        "threat_level": "medium",
        "event_type": "Network Scanning Activity",
        "description": "Port scanning detected from endpoint",
        "ip_address": "192.168.1.75",
        "user": "jane.smith",
        "hostname": "WORKSTATION-02",
        "attack_type": "discovery",
        "mitre_techniques": ["T1046"]
    }
]

# Sample Firewall logs
SAMPLE_FIREWALL_LOGS = [
    {
        "timestamp": "2024-02-11T12:00:00Z",
        "action": "denied",
        "source_ip": "203.0.113.45",
        "dest_ip": "192.168.1.10",
        "source_port": 54321,
        "dest_port": 22,
        "threat_detected": True
    },
    {
        "timestamp": "2024-02-11T12:05:00Z",
        "action": "blocked",
        "source_ip": "198.51.100.88",
        "dest_ip": "192.168.1.10",
        "source_port": 12345,
        "dest_port": 3389,
        "threat_detected": True
    }
]

# Sample IDS logs
SAMPLE_IDS_LOGS = [
    {
        "alert_id": "ids-001",
        "timestamp": "2024-02-11T13:00:00Z",
        "priority": 1,
        "signature": "SQL Injection Attempt",
        "description": "Detected SQL injection in web request",
        "src_ip": "203.0.113.99",
        "dst_ip": "192.168.1.20",
        "src_port": 45678,
        "dst_port": 443,
        "category": "web_attack"
    },
    {
        "alert_id": "ids-002",
        "timestamp": "2024-02-11T13:05:00Z",
        "priority": 2,
        "signature": "Malware Command and Control Traffic",
        "description": "Outbound connection to known C2 server",
        "src_ip": "192.168.1.50",
        "dst_ip": "198.51.100.100",
        "src_port": 49152,
        "dst_port": 8080,
        "category": "command_and_control"
    }
]

def get_all_sample_logs():
    """Get all sample logs for testing."""
    return {
        'siem': SAMPLE_SIEM_LOGS,
        'edr': SAMPLE_EDR_LOGS,
        'firewall': SAMPLE_FIREWALL_LOGS,
        'ids': SAMPLE_IDS_LOGS
    }
