"""
modules/xss.py — Cross-Site Scripting (Reflected, Stored indicators) + SSTI
OWASP A03:2021 - Injection
"""
from __future__ import annotations

import asyncio
from typing import List
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
        self.log("Starting XSS / SSTI scan")
        findings: List[Finding] = []

        endpoints = result.discovered_endpoints or [target]
        tasks = [self._test_reflected(url) for url in endpoints]
        tasks += [self._test_ssti(url) for url in endpoints]
        tasks += [self._test_post_xss(url) for url in endpoints]

        all_results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in all_results:
            if isinstance(r, list):
                findings.extend(r)

        for f in findings:
            self.add(f)
            result.add_finding(f)

        self.log(f"Found {len(findings)} XSS/SSTI issues")
        return findings

    async def _test_reflected(self, url: str) -> List[Finding]:
        findings: List[Finding] = []
        payloads = XSS["reflected"][:6]

        tasks, combos = [], []
        for param in self._PARAMS[:5]:
            for payload in payloads[:4]:
                for variant in PayloadMutator.mutate(payload, ["url", "html"])[:2]:
                    test_url = f"{url}?{param}={quote(variant, safe='')}"
                    combos.append((param, payload, variant, test_url))
                    tasks.append(self.engine.get(test_url))

        responses = await asyncio.gather(*tasks, return_exceptions=True)
        seen: set = set()

        for (param, orig, variant, test_url), resp in zip(combos, responses):
            if isinstance(resp, Exception) or not resp or url in seen:
                continue
            # Check raw (non-encoded) payload reflection
            if orig in resp.body:
                seen.add(url)
                ct = resp.headers.get("Content-Type", "")
                sev = "HIGH" if "text/html" in ct else "MEDIUM"
                f = Finding(
                    vuln_type       = "Cross-Site Scripting (Reflected)",
                    title           = "Reflected XSS Vulnerability",
                    endpoint        = url,
                    method          = "GET",
                    parameter       = param,
                    payload         = orig,
                    response_status = resp.status,
                    response_body   = resp.body[:600],
                    response_headers= resp.headers,
                    severity        = sev,
                    cvss_score      = CVSS_PROFILES["XSS_REFLECTED"]["score"],
                    cvss_vector     = CVSS_PROFILES["XSS_REFLECTED"]["vector"],
                    owasp_category  = self.OWASP_CATEGORY,
                    description     = (
                        f"Payload '{orig[:60]}' was reflected in the response without "
                        f"HTML encoding in parameter '{param}'. Attackers can inject scripts "
                        f"that execute in victims' browsers — enabling session hijacking, "
                        f"credential theft, and malicious redirects."
                    ),
                    recommendation  = (
                        "1. HTML-encode all user-supplied data before rendering (use context-aware escaping).\n"
                        "2. Implement a strict Content-Security-Policy header.\n"
                        "3. Use modern frameworks (React/Vue/Angular) that auto-escape output.\n"
                        "4. Set HttpOnly + Secure flags on session cookies.\n"
                        "5. Validate inputs with strict allowlists."
                    ),
                    references      = [
                        "https://owasp.org/www-community/attacks/xss/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                    ],
                    confirmed       = True,
                    module          = self.NAME,
                    tags            = ["xss", "reflected"],
                )
                findings.append(f)
                self.log(f"Reflected XSS: {url} param={param}", "FOUND")
        return findings

    async def _test_ssti(self, url: str) -> List[Finding]:
        """
        Server-Side Template Injection — sends math probes and checks for
        evaluated results in the response body.
        """
        findings: List[Finding] = []

        tasks, combos = [], []
        for param in self._PARAMS[:4]:
            for probe, expected in XSS["ssti_probes"]:
                if not expected:  # skip probes without a predictable result
                    continue
                test_url = f"{url}?{param}={quote(probe, safe='')}"
                combos.append((param, probe, expected, test_url))
                tasks.append(self.engine.get(test_url))

        responses = await asyncio.gather(*tasks, return_exceptions=True)
        seen: set = set()

        for (param, probe, expected, test_url), resp in zip(combos, responses):
            if isinstance(resp, Exception) or not resp or url in seen:
                continue
            if expected in resp.body:
                seen.add(url)
                f = Finding(
                    vuln_type       = "Server-Side Template Injection (SSTI)",
                    title           = "SSTI — Remote Code Execution Risk",
                    endpoint        = url,
                    method          = "GET",
                    parameter       = param,
                    payload         = probe,
                    response_status = resp.status,
                    response_body   = resp.body[:600],
                    severity        = "CRITICAL",
                    cvss_score      = CVSS_PROFILES["SSTI"]["score"],
                    cvss_vector     = CVSS_PROFILES["SSTI"]["vector"],
                    owasp_category  = self.OWASP_CATEGORY,
                    description     = (
                        f"The probe '{probe}' was server-evaluated to '{expected}', confirming SSTI. "
                        f"User input is passed directly to a template engine (Jinja2, Twig, Mako, EL, etc.). "
                        f"SSTI typically leads to Remote Code Execution — the most severe outcome."
                    ),
                    recommendation  = (
                        "1. Never pass user input to template render functions.\n"
                        "2. Use template sandboxing (Jinja2 SandboxedEnvironment).\n"
                        "3. Validate/reject template metacharacters in user input.\n"
                        "4. Consider a logic-less template engine if dynamic rendering is needed."
                    ),
                    references      = ["https://portswigger.net/web-security/server-side-template-injection"],
                    confirmed       = True,
                    module          = self.NAME,
                    tags            = ["ssti", "rce", "critical"],
                )
                findings.append(f)
                self.log(f"SSTI CONFIRMED: {url} probe={probe!r} → {expected}", "FOUND")
        return findings

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
                    module          = self.NAME,
                    tags            = ["xss", "post"],
                )
                findings.append(f)
                self.log(f"POST XSS: {url} field={key}", "FOUND")
                break
        return findings
