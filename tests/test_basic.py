"""Test the core functionality without requiring all dependencies."""
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

print("=" * 80)
print("Cyber Incident Response System - Basic Test")
print("=" * 80)
print()

# Test 1: Check project structure
print("✓ Test 1: Project Structure")
expected_dirs = [
    'src/cir/core',
    'src/cir/ingestion',
    'src/cir/detection',
    'src/cir/correlation',
    'src/cir/playbook',
    'src/cir/api',
    'config',
    'examples',
]

for dir_path in expected_dirs:
    full_path = os.path.join(os.path.dirname(__file__), '..', dir_path)
    if os.path.exists(full_path):
        print(f"  ✓ {dir_path}")
    else:
        print(f"  ✗ {dir_path} - NOT FOUND")

print()

# Test 2: Check configuration files
print("✓ Test 2: Configuration Files")
expected_files = [
    'config/config.yaml',
    '.env.example',
    'requirements.txt',
    'setup.py',
]

for file_path in expected_files:
    full_path = os.path.join(os.path.dirname(__file__), '..', file_path)
    if os.path.exists(full_path):
        print(f"  ✓ {file_path}")
    else:
        print(f"  ✗ {file_path} - NOT FOUND")

print()

# Test 3: Check sample data
print("✓ Test 3: Sample Data")
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'examples'))
    from sample_logs import get_all_sample_logs
    
    sample_logs = get_all_sample_logs()
    total_logs = sum(len(logs) for logs in sample_logs.values())
    print(f"  ✓ Sample logs available: {total_logs} total")
    for source, logs in sample_logs.items():
        print(f"    - {source.upper()}: {len(logs)} logs")
except Exception as e:
    print(f"  ✗ Error loading sample logs: {e}")

print()

# Test 4: Try importing modules (will fail if dependencies not installed)
print("✓ Test 4: Module Imports")
modules_to_test = [
    ('cir.core.models', 'Data Models'),
    ('cir.core.config', 'Configuration'),
    ('cir.ingestion.parsers', 'Log Parsers'),
    ('cir.detection.anomaly', 'Anomaly Detection'),
    ('cir.correlation.engine', 'Correlation Engine'),
    ('cir.playbook.generator', 'Playbook Generator'),
    ('cir.api.server', 'API Server'),
]

for module_name, description in modules_to_test:
    try:
        __import__(module_name)
        print(f"  ✓ {description} ({module_name})")
    except ImportError as e:
        print(f"  ⚠ {description} ({module_name}) - Missing dependencies")
        print(f"      {str(e)[:60]}")

print()
print("=" * 80)
print("Basic tests completed!")
print()
print("To install dependencies and run full demo:")
print("  pip install -r requirements.txt")
print("  python examples/demo.py")
print("=" * 80)
