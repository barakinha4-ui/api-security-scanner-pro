"""
core/logger.py — Structured logging for the API Security Scanner.
Ensures sensitive data is redacted and output is terminal-friendly.
"""
import logging
import sys
import re
from typing import Any, Dict, Optional

# Patterns for sensitive data redaction
SECRET_PATTERNS = [
    re.compile(r'(?:auth|token|key|password|secret|pwd|session|jwt)[\'"]?\s*[:=]\s*[\'"]?([^\'"\s]+)[\'"]?', re.IGNORECASE),
    re.compile(r'Bearer\s+([a-zA-Z0-9\-\._~+/]+=*)', re.IGNORECASE)
]

class RedactingFormatter(logging.Formatter):
    """
    Formatter that redacts secrets from log messages.
    """
    def __init__(self, fmt: Optional[str] = None):
        super().__init__(fmt)
        self.redact_enabled = True

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        if self.redact_enabled:
            for pattern in SECRET_PATTERNS:
                msg = pattern.sub(lambda m: m.group(0).replace(m.group(1), "[REDACTED]"), msg)
        return msg

def setup_logger(name: str = "apiscanner", level: int = logging.INFO, redact: bool = True) -> logging.Logger:
    """
    Configures a structured logger with color-coded levels.
    
    Args:
        name: Name of the logger.
        level: Logging level.
        redact: Whether to enable sensitive data redaction.
        
    Returns:
        logging.Logger: Configured logger instance.
        
    Example:
        >>> logger = setup_logger("scanner", level=logging.DEBUG)
        >>> logger.info("Scan started")
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        
        # Color coding for terminal
        fmt = "%(levelname)s: %(message)s"
        if sys.stdout.isatty():
            fmt = "\033[1;34m%(levelname)s\033[0m: %(message)s"
            
        formatter = RedactingFormatter(fmt)
        formatter.redact_enabled = redact
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
    return logger

# Global logger instance
logger = setup_logger()
