"""Example usage of the Cyber Incident Response system."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from cir.ingestion.parsers import LogIngestionEngine
from cir.detection.anomaly import AnomalyDetectionEngine
from cir.correlation.engine import CorrelationEngine
from cir.playbook.generator import PlaybookGenerator
from sample_logs import get_all_sample_logs


def main():
    """Demonstrate the incident response pipeline."""
    print("=" * 80)
    print("Cyber Incident Response System - Demo")
    print("=" * 80)
    print()
    
    # Step 1: Initialize engines
    print("Step 1: Initializing engines...")
    ingestion_engine = LogIngestionEngine()
    anomaly_engine = AnomalyDetectionEngine()
    correlation_engine = CorrelationEngine()
    playbook_generator = PlaybookGenerator()
    print("✓ All engines initialized\n")
    
    # Step 2: Ingest sample logs
    print("Step 2: Ingesting sample security logs...")
    sample_logs = get_all_sample_logs()
    all_alerts = []
    
    for source_type, logs in sample_logs.items():
        print(f"  - Ingesting {len(logs)} {source_type.upper()} logs...")
        alerts = ingestion_engine.ingest_batch(logs, source_type)
        all_alerts.extend(alerts)
        print(f"    ✓ Created {len(alerts)} alerts")
    
    print(f"\n✓ Total alerts created: {len(all_alerts)}\n")
    
    # Step 3: Train anomaly detection
    print("Step 3: Training anomaly detection models...")
    if len(all_alerts) >= 10:
        anomaly_engine.train(all_alerts)
        print("✓ Anomaly detection models trained\n")
    else:
        print("⚠ Not enough alerts for training (need at least 10)\n")
    
    # Step 4: Detect anomalies
    print("Step 4: Running anomaly detection on alerts...")
    if anomaly_engine.is_trained:
        for i, alert in enumerate(all_alerts[:3]):  # Show first 3
            result = anomaly_engine.detect(alert)
            print(f"  Alert: {alert.title}")
            print(f"    - Anomaly Score: {result.anomaly_score:.3f}")
            print(f"    - Is Anomaly: {result.is_anomaly}")
            print(f"    - Algorithms: {', '.join(result.algorithms_used)}")
            alert.anomaly_score = result.anomaly_score
            print()
    
    # Step 5: Correlate alerts into incidents
    print("Step 5: Correlating alerts into incidents...")
    incidents = correlation_engine.correlate_alerts(all_alerts)
    print(f"✓ Created {len(incidents)} incident(s)\n")
    
    # Show incident details
    for incident in incidents:
        print(f"Incident: {incident.id}")
        print(f"  - Title: {incident.title}")
        print(f"  - Severity: {incident.severity.value}")
        print(f"  - Alerts: {incident.alert_count}")
        print(f"  - Correlation Score: {incident.correlation_score:.2f}")
        print(f"  - Factors: {', '.join(incident.correlation_factors)}")
        if incident.affected_users:
            print(f"  - Affected Users: {', '.join(incident.affected_users)}")
        if incident.affected_systems:
            print(f"  - Affected Systems: {', '.join(incident.affected_systems)}")
        print()
    
    # Step 6: Generate playbooks
    print("Step 6: Generating incident response playbooks...")
    for incident in incidents[:2]:  # Generate for first 2 incidents
        print(f"\nGenerating playbook for: {incident.title}")
        playbook = playbook_generator.generate_playbook(incident)
        
        print(f"  Playbook ID: {playbook.id}")
        print(f"  Title: {playbook.title}")
        print(f"  Steps: {len(playbook.steps)}")
        print(f"  Estimated Duration: {playbook.estimated_duration}")
        print(f"\n  Response Steps:")
        
        for step in playbook.steps[:3]:  # Show first 3 steps
            print(f"    {step.step_number}. {step.title}")
            print(f"       Type: {step.action_type}")
            print(f"       Approval Required: {step.approval_required}")
        
        if len(playbook.steps) > 3:
            print(f"    ... and {len(playbook.steps) - 3} more steps")
        print()
    
    print("=" * 80)
    print("Demo completed successfully!")
    print("=" * 80)
    print("\nSummary:")
    print(f"  - Alerts processed: {len(all_alerts)}")
    print(f"  - Incidents created: {len(incidents)}")
    print(f"  - Playbooks generated: {min(len(incidents), 2)}")
    print(f"  - Anomaly detector trained: {anomaly_engine.is_trained}")
    print()


if __name__ == "__main__":
    main()
