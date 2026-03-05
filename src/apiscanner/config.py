"""
config.py — Global Configuration Management
Uses pydantic-settings to handle environment variables and defaults.
"""
from __future__ import annotations
from typing import Optional
from pydantic_settings import BaseSettings, Field

class ScannerConfig(BaseSettings):
    # Network
    max_concurrency: int = Field(20, ge=1, le=200)
    request_timeout: int = Field(10, ge=1, le=300)
    delay_between_requests: float = Field(0.2, ge=0)
    
    # Security & Privacy
    verify_ssl: bool = True
    redact_secrets_in_logs: bool = True
    include_request_response_in_report: bool = True
    enable_hot_reload: bool = False
    
    # OAST Integration
    oast_provider: Optional[str] = "interact.sh"
    oast_timeout: int = 30
    
    # Reporting
    report_format: str = Field("html", pattern="^(html|json|markdown|sarif)$")
    include_cvss_vector: bool = True
    

    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "allow"
