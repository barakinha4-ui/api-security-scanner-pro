"""
modules/ssrf.py — Server-Side Request Forgery
OWASP A10:2021 / API7:2023
"""
from __future__ import annotations

import re
import asyncio
from typing import List, Tuple
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
        self.log("Starting SSRF scan")
        findings: List[Finding] = []
        endpoints = result.discovered_endpoints or [target]

        tasks = []
        for url in endpoints:
            tasks.append(self._test_get_params(url))
            tasks.append(self._test_post_params(url))

        all_results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in all_results:
            if isinstance(r, list):
                findings.extend(r)

        for f in findings:
            self.add(f)
            result.add_finding(f)

        self.log(f"Found {len(findings)} SSRF issues")
        return findings

    async def _test_get_params(self, url: str) -> List[Finding]:
        findings: List[Finding] = []
        payloads = [
            (SSRF["cloud_metadata"][0],   "AWS Metadata", "CRITICAL"),
            (SSRF["cloud_metadata"][1],   "AWS IAM Credentials", "CRITICAL"),
            (SSRF["localhost"][0],         "Localhost Access", "HIGH"),
            (SSRF["localhost"][1],         "Localhost (hostname)", "HIGH"),
            (SSRF["internal_services"][0], "Redis Internal", "HIGH"),
            (SSRF["file_read"][0],         "Local File Read", "HIGH"),
        ]

        tasks, combos = [], []
        for param in SSRF["url_params"][:8]:
            for payload, label, sev in payloads:
                test_url = f"{url}?{param}={quote(payload, safe='')}"
                combos.append((param, payload, label, sev, test_url))
                tasks.append(self.engine.get(test_url))

        responses = await asyncio.gather(*tasks, return_exceptions=True)
        seen: set = set()

        for (param, payload, label, sev, test_url), resp in zip(combos, responses):
            if isinstance(resp, Exception) or not resp or url in seen:
                continue
            confirmed, evidence = self._analyse(resp, payload)
            if confirmed:
                seen.add(url)
                findings.append(self._make_finding(url, param, payload, label, sev,
                                                    resp, evidence, "GET"))
                self.log(f"SSRF: {url} param={param} → {label}", "FOUND")
        return findings

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
            confirmed, evidence = self._analyse(resp, payload)
            if confirmed:
                key = list(body.keys())[0]
                findings.append(self._make_finding(url, key, payload,
                                                    "AWS Metadata via POST", "CRITICAL",
                                                    resp, evidence, "POST"))
                self.log(f"POST SSRF: {url} field={key}", "FOUND")
                break
        return findings

    def _analyse(self, resp, payload: str) -> Tuple[bool, str]:
        if not resp.ok:
            return False, ""
        for pat in self._CONFIRM_PATTERNS:
            m = pat.search(resp.body)
            if m:
                return True, m.group(0)
        # Localhost: any 200 with substantial body is suspicious
        if ("127.0.0.1" in payload or "localhost" in payload) and resp.status == 200 and len(resp.body) > 30:
            return True, resp.body[:50]
        return False, ""

    def _make_finding(self, url, param, payload, label, severity,
                      resp, evidence, method) -> Finding:
        return Finding(
            vuln_type       = "Server-Side Request Forgery (SSRF)",
            title           = f"SSRF — {label}",
            endpoint        = url,
            method          = method,
            parameter       = param,
            payload         = payload,
            response_status = resp.status,
            response_body   = resp.body[:700],
            response_headers= resp.headers,
            response_time_ms= resp.elapsed_ms,
            severity        = severity,
            cvss_score      = CVSS_PROFILES["SSRF_CRITICAL" if severity == "CRITICAL" else "SSRF"]["score"],
            cvss_vector     = CVSS_PROFILES["SSRF_CRITICAL" if severity == "CRITICAL" else "SSRF"]["vector"],
            owasp_category  = self.OWASP_CATEGORY,
            description     = (
                f"SSRF confirmed via parameter '{param}'. The server fetched "
                f"'{payload}' and returned: '{evidence[:80]}'. "
                f"Attackers can scan internal networks, steal cloud credentials "
                f"(IAM/user-data), read local files, and pivot into internal services."
            ),
            recommendation  = (
                "1. Implement strict URL allowlisting — only specific, approved domains.\n"
                "2. Block requests to RFC 1918 ranges and link-local (169.254.0.0/16).\n"
                "3. Use a DNS resolver that blocks internal hostnames.\n"
                "4. Do not follow HTTP redirects from user-supplied URLs.\n"
                "5. On AWS/GCP/Azure: enforce IMDSv2 (token-required metadata access).\n"
                "6. Consider a dedicated egress proxy/sandbox for outbound requests."
            ),
            references      = [
                "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            ],
            confirmed       = True,
            module          = self.NAME,
            tags            = ["ssrf", label.lower().replace(" ", "-")],
        )
