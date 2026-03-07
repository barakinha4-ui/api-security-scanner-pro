"""
config.py — Global Configuration Management
Uses pydantic-settings to handle environment variables and defaults.
"""
from __future__ import annotations
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings

class ScannerConfig(BaseSettings):
    # Network
    max_concurrency: int = Field(30, ge=1, le=200)
    request_timeout: int = Field(4, ge=1, le=300)   # 4s is enough for most APIs
    delay_between_requests: float = Field(0.0, ge=0) # No delay — API server handles concurrency
    
    # Security & Privacy
    verify_ssl: bool = True
    redact_secrets_in_logs: bool = True
    include_request_response_in_report: bool = True
    enable_hot_reload: bool = False
    
    # Shield / Engine Safeguards
    allow_private_targets: bool = False
    rate_limit_per_minute: int = 1000
    api_key_required: bool = True
    
    # OAST Integration
    oast_provider: Optional[str] = "interact.sh"
    oast_timeout: int = 1  # Short timeout for faster public test APIs
    
    # Reporting
    report_format: str = Field("html", pattern="^(html|json|markdown|sarif)$")
    include_cvss_vector: bool = True
    

    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "allow"
