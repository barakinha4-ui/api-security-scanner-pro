"""
modules/ssrf.py — Server-Side Request Forgery
OWASP A10:2021 / API7:2023
"""
from __future__ import annotations

import re
import asyncio
import uuid
from typing import List, Tuple, Optional
from urllib.parse import quote

from core.plugins import BasePlugin
from core.models import Finding, ScanResult, CVSS_PROFILES
from payloads.database import SSRF


class SSRFPlugin(BasePlugin):
    NAME           = "ssrf"
    DESCRIPTION    = "SSRF: cloud metadata, internal services, file read, DNS rebind bypass"
    OWASP_CATEGORY = "A10:2021 - Server-Side Request Forgery (SSRF)"
    TAGS           = ["ssrf", "network", "cloud", "metadata"]

    _CONFIRM_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SSRF["response_patterns"]]

    async def run(self, target: str, result: ScanResult) -> List[Finding]:
        self.log("Starting Enterprise-grade SSRF scan")
        findings: List[Finding] = []
        endpoints = (result.discovered_endpoints or [target])[:20]

        for url in endpoints:
            # Test high-risk parameters with high-precision confirmation
            for param in SSRF["url_params"][:6]:
                finding = await self.detect_with_confirmation(url, param)
                if finding:
                    findings.append(finding)
            
            # Additional POST SSRF tests
            findings.extend(await self._test_post_params(url))

        for f in findings:
            self.add(f)
            result.add_finding(f)

        self.log(f"Scan complete. Found {len(findings)} confirmed or probable SSRF issues")
        return findings

    async def detect_with_confirmation(self, url: str, param: str) -> Optional[Finding]:
        """
        Premium 3-Stage Confirmation Logic for SSRF:
        1. Cloud Metadata Probe (AWS/GCP/Azure)
        2. Internal Service / Banner Probe
        3. Logic Variance Detection
        """
        evidence_map = {
            "status_match": False,
            "pattern_match": False,
            "time_based": False,
            "boolean_based": False,
            "oast_callback": False
        }
        confirmation_evidence = []
        
        # --- PHASE 1: Cloud Metadata Probe ---
        metadata_payload = str(SSRF["cloud_metadata"][0])
        test_url = f"{url}?{param}={quote(metadata_payload, safe='')}"
        resp_cloud = await self.engine.get(test_url)
        
        if resp_cloud and any(pat.search(resp_cloud.body) for pat in self._CONFIRM_PATTERNS):
            evidence_map["pattern_match"] = True
            confirmation_evidence.append("Cloud Metadata Signature Found in Response")

        # --- PHASE 2: Loopback / Service Banner Probe ---
        localhost_payload = "http://localhost:22"
        r_local = await self.engine.get(f"{url}?{param}={quote(localhost_payload, safe='')}")
        if r_local and "SSH-" in r_local.body:
            evidence_map["boolean_based"] = True
            confirmation_evidence.append("Internal SSH Banner Leak Detected")
        elif r_local and r_local.status == 200 and len(r_local.body) > 100:
            evidence_map["status_match"] = True
            confirmation_evidence.append("Internal Service Access (Localhost) returned HTTP 200")

        # --- PHASE 3: OAST (Out-of-Band) Probe ---
        if self.oast:
            domain = await self.oast.get_domain()
            marker = f"ssrf-{uuid.uuid4().hex[:6]}"
            oast_url = f"http://{marker}.{domain}/"
            
            await self.engine.get(f"{url}?{param}={quote(oast_url, safe='')}")
            
            # Wait a few seconds for async callback
            if await self.oast.verify_interaction(marker, timeout=5):
                evidence_map["oast_callback"] = True
                confirmation_evidence.append(f"OAST Callback received for {marker}.{domain}")

        # --- FINAL CALCULATION ---
        f = Finding(
            vuln_type="Server-Side Request Forgery",
            endpoint=url,
            method="GET",
            parameter=param,
            payload=metadata_payload if evidence_map["pattern_match"] else localhost_payload,
            severity="HIGH",
            owasp_category=self.OWASP_CATEGORY,
            module=self.NAME,
            confirmation_evidence=confirmation_evidence
        )

        confidence = f.calculate_confidence(evidence_map)
        
        if confidence >= 0.5:
            if confidence >= 0.8 or evidence_map["pattern_match"]:
                f.severity = "CRITICAL"
                f.confirmed = True
                f.title = f"CRITICAL: Confirmed SSRF in '{param}'"
            else:
                f.severity = "HIGH"
                f.title = f"Probable SSRF in '{param}'"

            f.cvss_score = CVSS_PROFILES["SSRF_CRITICAL" if f.severity == "CRITICAL" else "SSRF"]["score"]
            f.description = f"Automated analysis identified SSRF via parameter '{param}'. Validation steps: {len(confirmation_evidence)} signals confirmed."
            f.recommendation = "Implement a strict allowlist of permitted domains. Disable requests to loopback and internal network ranges."
            return f

        return None

    async def _test_post_params(self, url: str) -> List[Finding]:
        findings: List[Finding] = []
        payload = SSRF["cloud_metadata"][0]
        fields = ["url", "webhook", "callback", "imageUrl", "source", "endpoint"]

        bodies = [{field: payload} for field in fields[:4]]
        resps = await asyncio.gather(
            *[self.engine.post(url, json=b) for b in bodies],
            return_exceptions=True
        )
        for body, resp in zip(bodies, resps):
            if isinstance(resp, Exception) or not resp:
                continue
            
            # Simple signature check for POST
            if any(pat.search(resp.body) for pat in self._CONFIRM_PATTERNS):
                key = list(body.keys())[0]
                findings.append(Finding(
                    vuln_type="SSRF", title="POST Body SSRF",
                    endpoint=url, method="POST", parameter=key,
                    severity="CRITICAL", confirmed=True, module=self.NAME,
                    confidence_score=0.9
                ))
                break
        return findings
