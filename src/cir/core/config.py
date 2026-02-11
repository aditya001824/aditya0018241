"""Configuration management."""
import os
from typing import Any, Dict, List
import yaml
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Application
    app_name: str = Field(default="CyberIncidentResponse", env="APP_NAME")
    app_version: str = Field(default="0.1.0", env="APP_VERSION")
    environment: str = Field(default="development", env="ENVIRONMENT")
    
    # API
    api_host: str = Field(default="0.0.0.0", env="API_HOST")
    api_port: int = Field(default=8000, env="API_PORT")
    api_workers: int = Field(default=4, env="API_WORKERS")
    
    # Elasticsearch
    elasticsearch_host: str = Field(default="localhost", env="ELASTICSEARCH_HOST")
    elasticsearch_port: int = Field(default=9200, env="ELASTICSEARCH_PORT")
    elasticsearch_index_prefix: str = Field(default="cir_", env="ELASTICSEARCH_INDEX_PREFIX")
    
    # Ollama
    ollama_host: str = Field(default="http://localhost:11434", env="OLLAMA_HOST")
    ollama_model: str = Field(default="llama2", env="OLLAMA_MODEL")
    ollama_timeout: int = Field(default=300, env="OLLAMA_TIMEOUT")
    
    # Detection
    anomaly_contamination: float = Field(default=0.1, env="ANOMALY_CONTAMINATION")
    anomaly_threshold: float = Field(default=0.75, env="ANOMALY_THRESHOLD")
    tsfresh_n_jobs: int = Field(default=4, env="TSFRESH_N_JOBS")
    
    # Correlation
    correlation_time_window: int = Field(default=300, env="CORRELATION_TIME_WINDOW")
    correlation_min_score: float = Field(default=0.6, env="CORRELATION_MIN_SCORE")
    
    # Alerts
    alert_retention_days: int = Field(default=90, env="ALERT_RETENTION_DAYS")
    max_alerts_per_query: int = Field(default=1000, env="MAX_ALERTS_PER_QUERY")
    
    # Logging
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_format: str = Field(default="json", env="LOG_FORMAT")
    
    class Config:
        env_file = ".env"
        case_sensitive = False


class ConfigManager:
    """Manages configuration from YAML files and environment."""
    
    def __init__(self, config_path: str = "config/config.yaml"):
        self.config_path = config_path
        self.config: Dict[str, Any] = {}
        self.settings = Settings()
        self.load_config()
    
    def load_config(self) -> None:
        """Load configuration from YAML file."""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f) or {}
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key (supports dot notation)."""
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        return value
    
    def get_detection_config(self) -> Dict[str, Any]:
        """Get detection configuration."""
        return self.config.get('detection', {})
    
    def get_correlation_config(self) -> Dict[str, Any]:
        """Get correlation configuration."""
        return self.config.get('correlation', {})
    
    def get_playbook_config(self) -> Dict[str, Any]:
        """Get playbook configuration."""
        return self.config.get('playbook', {})
    
    def get_ingestion_config(self) -> Dict[str, Any]:
        """Get ingestion configuration."""
        return self.config.get('ingestion', {})


# Global configuration instance
config_manager = ConfigManager()
settings = config_manager.settings
