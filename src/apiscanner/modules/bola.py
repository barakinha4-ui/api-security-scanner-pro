"""
modules/bola.py — Broken Object Level Authorization (BOLA)
OWASP API1:2023
Tests for unauthorized access by manipulating IDs (Numeric, UUID, Hashes).
"""
from __future__ import annotations
import re
import asyncio
import uuid
from typing import List, Optional, Dict, Any, cast

from core.plugins import BasePlugin
from core.models import Finding, ScanResult, CVSS_PROFILES

class BOLAPlugin(BasePlugin):
    NAME = "bola"
    DESCRIPTION = "BOLA/IDOR detection via identifier manipulation and unauthorized access mapping"
    OWASP_CATEGORY = "API1:2023 - Broken Object Level Authorization"
    TAGS = ["bola", "idor", "auth"]

    async def run(self, target: str, result: ScanResult) -> List[Finding]:
        self.log("Starting BOLA/IDOR analysis")
        findings: List[Finding] = []
        endpoints = (result.discovered_endpoints or [target])[:20]

        # Targets with potential object IDs in path: /api/v1/user/123 or /api/orders/ABC-123
        bola_targets = [u for u in endpoints if re.search(r'/\d+|/[a-f0-9-]{32,}', u.lower())]
        
        for url in bola_targets:
            f = await self.test_url_bola(url)
            if f:
                findings.append(f)
                self.add(f)
                result.add_finding(f)

        return findings

    async def test_url_bola(self, url: str) -> Optional[Finding]:
        """
        Attempts BOLA by:
        1. Identifying the ID in the path
        2. Attempting to access it with a different user context (if provided)
        3. Attempting to guess nearby IDs (numeric or UUID patterns)
        """
        # Example URL: http://api.target.com/api/users/1001
        match = re.search(r'/(?P<id>\d+|[a-f0-9-]{32,36})($|/)', url)
        if not match: return None

        obj_id = match.group('id')
        prefix = url[:match.start('id')]
        suffix = url[match.end('id'):]

        # 1. Sequential ID Guessing (Numeric)
        if obj_id.isdigit():
            neighbors = [str(int(obj_id) - 1), str(int(obj_id) + 1)]
            for nid in neighbors:
                target_url = f"{prefix}{nid}{suffix}"
                res = await self.engine.get(target_url)
                if res and res.status == 200 and len(res.body) > 100:
                    # Potential BOLA if we get a 200 on a neighbor ID
                    return self._create_finding(url, target_url, "Numeric ID Guessing")

        # 2. UUID Guessing (if applicable)
        # Low success rate without secondary leak, but we check if nearby UUIDs or version variants work
        elif len(obj_id) >= 32:
            # Simple check: change last group of UUID
            if "-" in obj_id: # UUID format
                parts = obj_id.split("-")
                parts[-1] = "000000000000" # Test a dummy/default UUID
                test_uuid = "-".join(parts)
                target_url = f"{prefix}{test_uuid}{suffix}"
                res = await self.engine.get(target_url)
                if res and res.status == 200:
                    return self._create_finding(url, target_url, "UUID Manipulation")

        # 3. Double-Context Test (Most Reliable)
        attacker_token = self.config.get("auth_attacker")
        if attacker_token:
            headers = {"Authorization": attacker_token}
            res = await self.engine.get(url, headers=headers)
            if res and res.status == 200:
                f = self._create_finding(url, url, "Authorization Bypass (Cross-User)")
                f.confidence_score = 1.0
                f.confirmed = True
                f.severity = "HIGH"
                return f

        # 4. JSON Body BOLA Injection
        # Often IDs are in the body. We test if changing an ID in POST/PUT works.
        if "/api/" in url.lower():
            common_id_fields = ["id", "userId", "user_id", "account_id", "owner_id", "creator_id"]
            for field in common_id_fields:
                payload = {field: "1"} # Simple test value
                res = await self.engine.post(url, json=payload)
                if res and res.status == 200 and "application/json" in res.content_type:
                    return self._create_finding(url, url, f"JSON Body Injection ({field})")

        return None

    def _create_finding(self, original_url: str, injected_url: str, method: str) -> Finding:
        return Finding(
            vuln_type="Broken Object Level Authorization (BOLA)",
            title=f"BOLA detected via {method}",
            endpoint=original_url,
            method="GET",
            payload=injected_url,
            severity="MEDIUM",
            owasp_category=self.OWASP_CATEGORY,
            module=self.NAME,
            description=f"Automated testing accessed resources of another entity by manipulating identifiers in the URL. Technique: {method}.",
            recommendation="Implement fine-grained object-level authorization checks. Ensure users can only access resources they own.",
            cvss_score=CVSS_PROFILES["IDOR"]["score"]
        )
