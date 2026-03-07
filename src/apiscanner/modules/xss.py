"""
modules/xss.py — Cross-Site Scripting (Reflected, Stored indicators) + SSTI
OWASP A03:2021 - Injection
"""
from __future__ import annotations

import asyncio
from typing import List, Optional, Tuple
from urllib.parse import quote

from core.plugins import BasePlugin
from core.models import Finding, ScanResult, CVSS_PROFILES
from payloads.database import XSS, PayloadMutator


class XSSPlugin(BasePlugin):
    NAME           = "xss"
    DESCRIPTION    = "Reflected XSS, SSTI (Jinja2/Twig/EL), stored XSS indicators"
    OWASP_CATEGORY = "A03:2021 - Injection (XSS / SSTI)"
    TAGS           = ["xss", "ssti", "injection", "client-side"]

    _PARAMS = ["q", "search", "name", "msg", "message", "redirect",
               "next", "error", "callback", "title", "text", "query",
               "comment", "input", "data", "value", "content"]

    async def run(self, target: str, result: ScanResult) -> List[Finding]:
        self.log("Starting Enterprise XSS / SSTI scan")
        findings: List[Finding] = []
        endpoints = (result.discovered_endpoints or [target])[:20]

        for url in endpoints:
            # High-precision scan on common parameters
            count = 0
            for param in self._PARAMS:
                if count >= 8: break
                finding = await self.detect_with_confirmation(url, param)
                if finding:
                    findings.append(finding)
                count += 1
            
            # Additional POST tests
            findings.extend(await self._test_post_xss(url))

        for f in findings:
            self.add(f)
            result.add_finding(f)

        self.log(f"Scan complete. Found {len(findings)} confirmed XSS/SSTI issues")
        return findings

    async def detect_with_confirmation(self, url: str, param: str) -> Optional[Finding]:
        """
        Premium Confirmation Logic:
        Stage 1: Multi-probe SSTI verification
        Stage 2: Context-aware XSS reflection analysis
        """
        evidence_map = {
            "status_match": False,
            "pattern_match": False,
            "time_based": False,
            "boolean_based": False
        }
        confirmation_evidence = []

        # -- Stage 1: SSTI 2-Step Verification --
        probe1, expected1 = ("{{7*7}}", "49")
        probe2, expected2 = ("{{1337*2}}", "2674")
        
        r1 = await self.engine.get(f"{url}?{param}={quote(probe1, safe='')}")
        if r1 and not isinstance(r1, Exception) and r1.body and expected1 in r1.body:
            r2 = await self.engine.get(f"{url}?{param}={quote(probe2, safe='')}")
            if r2 and not isinstance(r2, Exception) and r2.body and expected2 in r2.body:
                evidence_map["boolean_based"] = True
                confirmation_evidence.append("SSTI Confirmed: Double-math evaluation (7*7 and 1337*2) successful")

                return Finding(
                    vuln_type="SSTI (Confirmed)",
                    title=f"Confirmed SSTI in '{param}'",
                    endpoint=url, method="GET", parameter=param, payload=probe2,
                    severity="CRITICAL", confirmed=True, 
                    owasp_category=self.OWASP_CATEGORY, module=self.NAME,
                    confirmation_evidence=confirmation_evidence,
                    confidence_score=1.0,
                    description=f"Server-Side Template Injection confirmed via expression evaluation.",
                    recommendation="Never pass user input to template engine render functions. Use sandboxed environments if necessary."
                )

        # -- Stage 2: XSS Reflection Analysis --
        xss_probe = "z'x\"y<v>w"
        r_xss = await self.engine.get(f"{url}?{param}={quote(xss_probe, safe='')}")
        
        if r_xss and not isinstance(r_xss, Exception) and r_xss.body:
            if xss_probe in r_xss.body:
                evidence_map["pattern_match"] = True
                confirmation_evidence.append("XSS Confirmed: Full payload reflection with special characters ('\"<>)")
                
                f = Finding(
                    vuln_type="Reflected Cross-Site Scripting (XSS)",
                    title=f"CRITICAL: Confirmed XSS in '{param}'",
                    endpoint=url, method="GET", parameter=param, payload=xss_probe,
                    severity="HIGH", confirmed=True,
                    owasp_category=self.OWASP_CATEGORY, module=self.NAME,
                    confirmation_evidence=confirmation_evidence
                )
                f.calculate_confidence(evidence_map)
                return f
            
        return None


    async def _test_post_xss(self, url: str) -> List[Finding]:
        """Tests POST body fields for XSS reflection."""
        findings: List[Finding] = []
        payload = "<script>alert('XSS')</script>"
        bodies = [{"name": payload}, {"comment": payload}, {"message": payload}]

        resps = await asyncio.gather(
            *[self.engine.post(url, json=b) for b in bodies],
            return_exceptions=True
        )
        for body, resp in zip(bodies, resps):
            if isinstance(resp, Exception) or not resp:
                continue
            if payload in resp.body:
                key = list(body.keys())[0]
                f = Finding(
                    vuln_type       = "XSS in POST Body",
                    title           = f"XSS Reflected from POST Field '{key}'",
                    endpoint        = url,
                    method          = "POST",
                    parameter       = key,
                    payload         = payload,
                    response_status = resp.status,
                    response_body   = resp.body[:500],
                    severity        = "HIGH",
                    cvss_score      = CVSS_PROFILES["XSS_REFLECTED"]["score"],
                    cvss_vector     = CVSS_PROFILES["XSS_REFLECTED"]["vector"],
                    owasp_category  = self.OWASP_CATEGORY,
                    description     = f"XSS payload reflected in POST body field '{key}'.",
                    recommendation  = "Encode all output regardless of input source (GET/POST/headers).",
                    confirmed       = True,
                    confidence_score= 0.95,
                    module          = self.NAME,
                    tags            = ["xss", "post"],
                )
                findings.append(f)
                self.log(f"POST XSS: {url} field={key}", "FOUND")
                break
        return findings
