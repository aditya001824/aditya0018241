# Cyber Incident Response System

An autonomous AI-powered cyber incident response tool designed for banking environments, featuring real-time threat detection, intelligent alert correlation, and automated playbook generation.

## 🎯 Overview

This system provides a comprehensive solution for automated cyber incident response, leveraging AI/ML for:
- **Security Alert Ingestion**: Multi-format log parsing (SIEM, EDR, Firewall, IDS)
- **Anomaly Detection**: PyOD-based outlier detection with UEBA analytics
- **Incident Correlation**: Intelligent grouping of related alerts
- **Automated Playbook Generation**: LLM-powered incident response playbooks
- **Zero External Dependencies**: Fully local operation with no data leakage

## 🚀 Quick Start

### Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

### Running the Demo

```bash
# Run the demonstration
python examples/demo.py
```

## 🔧 Technology Stack

- **Core Framework**: Python 3.9+
- **API**: FastAPI, Uvicorn
- **ML/AI**: PyOD, scikit-learn, tsfresh
- **LLM**: LangChain, Ollama
- **Data Processing**: Pandas, NumPy

---

**Built with ❤️ for secure, autonomous incident response**
