"""
modules/misconfig.py — Security Misconfiguration
OWASP API8:2023 + A02:2021 + API4:2023
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import List

from core.plugins import BasePlugin
from core.models import Finding, ScanResult, CVSS_PROFILES
from payloads.database import SECURITY_HEADERS, SENSITIVE_PATTERNS


class MisconfigPlugin(BasePlugin):
    NAME           = "misconfig"
    DESCRIPTION    = "Security headers, CORS, SSL/TLS, rate limiting, mass assignment, sensitive data"
    OWASP_CATEGORY = "API8:2023 - Security Misconfiguration"
    TAGS           = ["headers", "cors", "ssl", "rate-limit", "mass-assignment", "sensitive-data"]

    async def run(self, target: str, result: ScanResult) -> List[Finding]:
        self.log("Starting misconfiguration scan")
        findings: List[Finding] = []

        base_resp = await self.engine.get(target)
        endpoints = (result.discovered_endpoints or [target])[:20]

        tasks = [
            self._test_security_headers(target, base_resp),
            self._test_cors(target),
            self._test_ssl(target),
            self._test_rate_limiting(target, endpoints),
            self._test_mass_assignment(target, endpoints),
            self._test_sensitive_data(endpoints[:12]),
            self._test_debug_endpoints(target, result),
            self._test_ratelimit_bypass(target, endpoints),
        ]
        all_results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in all_results:
            if isinstance(r, list):
                findings.extend(r)

        for f in findings:
            self.add(f)
            result.add_finding(f)

        self.log(f"Found {len(findings)} misconfiguration issues")
        return findings

    # ── Security Headers ──────────────────────────────────────────────────

    async def _test_security_headers(self, url: str, resp) -> List[Finding]:
        findings: List[Finding] = []
        if not resp or not resp.ok:
            return findings

        h = resp.headers_lower

        # Required headers
        for header, recommended_value in SECURITY_HEADERS["required"].items():
            if header.lower() not in h:
                sev_map = {
                    "Content-Security-Policy":    "MEDIUM",
                    "Strict-Transport-Security":  "MEDIUM",
                    "X-Frame-Options":            "MEDIUM",
                    "X-Content-Type-Options":     "LOW",
                    "Referrer-Policy":            "LOW",
                    "Permissions-Policy":         "LOW",
                }
                sev = sev_map.get(header, "LOW")
                f = Finding(
                    vuln_type       = f"Missing Security Header: {header}",
                    title           = f"Security Header Missing: {header}",
                    endpoint        = url,
                    method          = "GET",
                    payload         = f"Response missing '{header}' header",
                    response_headers= resp.headers,
                    severity        = sev,
                    cvss_score      = CVSS_PROFILES["MISSING_HEADER"]["score"],
                    cvss_vector     = CVSS_PROFILES["MISSING_HEADER"]["vector"],
                    owasp_category  = self.OWASP_CATEGORY,
                    description     = f"The security header '{header}' is absent, leaving the application exposed to related client-side attacks.",
                    recommendation  = f"Add: `{header}: {recommended_value}`",
                    module          = self.NAME,
                    tags            = ["headers", "misconfiguration"],
                )
                findings.append(f)

        # Information-leaking headers
        for header in SECURITY_HEADERS["leaking"]:
            val = h.get(header.lower())
            if val and len(val) > 2:
                f = Finding(
                    vuln_type       = f"Server Fingerprinting Header: {header}",
                    title           = f"Tech Stack Revealed by '{header}' Header",
                    endpoint        = url,
                    method          = "GET",
                    payload         = f"{header}: {val}",
                    response_headers= resp.headers,
                    severity        = "LOW",
                    cvss_score      = 3.1,
                    cvss_vector     = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    owasp_category  = self.OWASP_CATEGORY,
                    description     = f"Header '{header}: {val}' reveals technology details, aiding targeted attacks.",
                    recommendation  = f"Remove or replace '{header}' with a generic value (e.g., Server: webserver).",
                    module          = self.NAME,
                    tags            = ["headers", "fingerprinting"],
                )
                findings.append(f)
        return findings

    # ── CORS ──────────────────────────────────────────────────────────────

    async def _test_cors(self, url: str) -> List[Finding]:
        findings: List[Finding] = []
        evil = "https://evil-attacker.com"

        resp = await self.engine.options(url, headers={
            "Origin": evil,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Authorization",
        })
        if not resp:
            return findings

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == "*":
            is_crit = (acac == "true")
            f = Finding(
                vuln_type       = "CORS Wildcard Origin",
                title           = "CORS Wildcard" + (" + Credentials: Data Theft Possible" if is_crit else ""),
                endpoint        = url,
                method          = "OPTIONS",
                payload         = f"Origin: {evil}",
                response_status = resp.status,
                response_headers= resp.headers,
                response_body   = f"ACAO: {acao} | ACAC: {acac}",
                severity        = "CRITICAL" if is_crit else "MEDIUM",
                cvss_score      = CVSS_PROFILES["CORS_WILDCARD"]["score"],
                cvss_vector     = CVSS_PROFILES["CORS_WILDCARD"]["vector"],
                owasp_category  = self.OWASP_CATEGORY,
                description     = (
                    "CORS wildcard (*) is set" +
                    (". Combined with Allow-Credentials: true, any site can make "
                     "authenticated cross-origin requests and steal user data." if is_crit
                     else ".")
                ),
                recommendation  = (
                    "1. Replace * with an explicit allowlist of trusted origins.\n"
                    "2. Never combine Allow-Origin: * with Allow-Credentials: true.\n"
                    "3. Validate the Origin header against the allowlist server-side."
                ),
                confirmed       = True,
                module          = self.NAME,
                tags            = ["cors", "wildcard"],
            )
            findings.append(f)
            self.log(f"CORS wildcard: {url}", "FOUND")

        elif acao == evil:
            f = Finding(
                vuln_type       = "CORS Origin Reflection",
                title           = "CORS Reflects Arbitrary Origin Without Validation",
                endpoint        = url,
                method          = "OPTIONS",
                payload         = f"Origin: {evil}",
                response_headers= resp.headers,
                response_body   = f"Reflected ACAO: {acao}",
                severity        = "HIGH",
                cvss_score      = CVSS_PROFILES["CORS_REFLECT"]["score"],
                cvss_vector     = CVSS_PROFILES["CORS_REFLECT"]["vector"],
                owasp_category  = self.OWASP_CATEGORY,
                description     = "Server reflects any Origin header value, allowing cross-origin requests from attacker-controlled sites.",
                recommendation  = "Validate Origin against a strict allowlist. Never echo the received Origin unconditionally.",
                confirmed       = True,
                module          = self.NAME,
                tags            = ["cors", "reflection"],
            )
            findings.append(f)
            self.log(f"CORS reflection: {url}", "FOUND")
        return findings

    # ── SSL / TLS ─────────────────────────────────────────────────────────

    async def _test_ssl(self, target: str) -> List[Finding]:
        findings: List[Finding] = []

        if target.startswith("https://"):
            http_url = "http://" + target[8:]
            resp = await self.engine.get(http_url)
            if resp and resp.status == 200 and resp.ok:
                f = Finding(
                    vuln_type       = "HTTP Access Without HTTPS Redirect",
                    title           = "API Accessible Over Unencrypted HTTP",
                    endpoint        = http_url,
                    method          = "GET",
                    response_status = resp.status,
                    severity        = "HIGH",
                    cvss_score      = CVSS_PROFILES["SSL_HTTP"]["score"],
                    cvss_vector     = CVSS_PROFILES["SSL_HTTP"]["vector"],
                    owasp_category  = "A02:2021 - Cryptographic Failures",
                    description     = "The API responds to plain HTTP without redirecting to HTTPS. All traffic is exposed to interception.",
                    recommendation  = "Force HTTPS via 301 redirect. Add HSTS header. Disable HTTP at the load balancer.",
                    confirmed       = True,
                    module          = self.NAME,
                    tags            = ["ssl", "http"],
                )
                findings.append(f)
                self.log(f"HTTP accessible (no redirect): {http_url}", "FOUND")

        elif target.startswith("http://"):
            f = Finding(
                vuln_type       = "No TLS — API on Plain HTTP",
                title           = "API Running Without TLS — All Traffic Unencrypted",
                endpoint        = target,
                method          = "GET",
                severity        = "CRITICAL",
                cvss_score      = 9.1,
                cvss_vector     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                owasp_category  = "A02:2021 - Cryptographic Failures",
                description     = "API is on HTTP. All data (credentials, tokens, PII) is transmitted in clear text.",
                recommendation  = "Deploy a TLS certificate (Let's Encrypt is free). Enforce HTTPS-only on the server and load balancer.",
                confirmed       = True,
                module          = self.NAME,
                tags            = ["ssl", "no-tls", "critical"],
            )
            findings.append(f)
            self.log(f"No TLS: {target}", "FOUND")
        return findings

    # ── Rate Limiting ─────────────────────────────────────────────────────

    async def _test_rate_limiting(self, target: str, endpoints: List[str]) -> List[Finding]:
        findings: List[Finding] = []

        candidates = [
            e for e in endpoints
            if any(kw in e for kw in ["/api", "/v1", "/v2", "search", "users"])
        ][:2] or [target]

        for url in candidates[:2]:
            old_delay = self.engine.base_delay
            self.engine.base_delay = 0.03
            resps = await asyncio.gather(
                *[self.engine.get(url) for _ in range(15)],
                return_exceptions=True
            )
            self.engine.base_delay = old_delay

            codes = [r.status for r in resps if not isinstance(r, Exception) and r and r.ok]
            if len(codes) >= 12 and 429 not in codes:
                rate_headers = any(
                    h in {k.lower() for k in (resps[-1].headers if resps[-1] and not isinstance(resps[-1], Exception) else {}).keys()}
                    for h in ["x-ratelimit-limit", "retry-after", "x-rate-limit-limit"]
                )
                if not rate_headers:
                    f = Finding(
                        vuln_type       = "No Rate Limiting on API Endpoint",
                        title           = "Rate Limiting Missing — Endpoint Open to Abuse",
                        endpoint        = url,
                        method          = "GET",
                        payload         = "15 rapid requests, no throttling",
                        response_body   = f"All 15 returned {set(codes)}. No 429.",
                        severity        = "MEDIUM",
                        cvss_score      = CVSS_PROFILES["RATE_LIMIT"]["score"],
                        cvss_vector     = CVSS_PROFILES["RATE_LIMIT"]["vector"],
                        owasp_category  = "API4:2023 - Unrestricted Resource Consumption",
                        description     = "No rate limiting detected — endpoint accepts unlimited rapid requests, enabling DoS, scraping, and brute force.",
                        recommendation  = (
                            "1. Implement rate limiting (100 req/min per IP baseline).\n"
                            "2. Return 429 with Retry-After header when exceeded.\n"
                            "3. Add X-RateLimit-Limit / X-RateLimit-Remaining headers.\n"
                            "4. Use a reverse proxy (nginx, Cloudflare) for global limits."
                        ),
                        confirmed       = True,
                        module          = self.NAME,
                        tags            = ["rate-limit", "dos"],
                    )
                    findings.append(f)
                    self.log(f"No rate limit: {url}", "FOUND")
        return findings

    # ── Rate Limit Bypass ─────────────────────────────────────────────────

    async def _test_ratelimit_bypass(self, target: str, endpoints: List[str]) -> List[Finding]:
        """
        Tests rate-limit bypass via header manipulation:
        Some servers only throttle by the IP in X-Forwarded-For,
        which clients can spoof.
        """
        findings: List[Finding] = []
        url = (endpoints[:1] or [target])[0]

        # First confirm rate limiting is actually in place
        old_delay = self.engine.base_delay
        self.engine.base_delay = 0.03
        check_resps = await asyncio.gather(
            *[self.engine.get(url) for _ in range(8)],
            return_exceptions=True
        )
        self.engine.base_delay = old_delay

        has_rate_limit = 429 in [
            r.status for r in check_resps
            if not isinstance(r, Exception) and r
        ]
        if not has_rate_limit:
            return findings  # No rate limit to bypass

        # Try bypass by rotating X-Forwarded-For IPs
        bypass_resps = await asyncio.gather(
            *[
                self.engine.get(url, headers={"X-Forwarded-For": f"203.0.113.{i}"})
                for i in range(10)
            ],
            return_exceptions=True
        )
        bypass_codes = [r.status for r in bypass_resps if not isinstance(r, Exception) and r]
        if bypass_codes and 429 not in bypass_codes and all(c == 200 for c in bypass_codes):
            f = Finding(
                vuln_type       = "Rate Limit Bypass via Header Spoofing",
                title           = "Rate Limit Bypassable via X-Forwarded-For Rotation",
                endpoint        = url,
                method          = "GET",
                payload         = "X-Forwarded-For: 203.0.113.{0..9}",
                response_body   = f"Bypassed with codes: {set(bypass_codes)}",
                severity        = "HIGH",
                cvss_score      = CVSS_PROFILES["RATELIMIT_BYPASS"]["score"],
                cvss_vector     = CVSS_PROFILES["RATELIMIT_BYPASS"]["vector"],
                owasp_category  = "API4:2023 - Unrestricted Resource Consumption",
                description     = (
                    "Rate limiting is implemented but uses X-Forwarded-For for IP tracking. "
                    "Clients can rotate this header to bypass throttling completely."
                ),
                recommendation  = (
                    "1. Use the real client IP (TCP connection source) for rate limiting.\n"
                    "2. Only trust X-Forwarded-For from known upstream proxies.\n"
                    "3. Implement rate limiting at the network layer (not just application)."
                ),
                confirmed       = True,
                module          = self.NAME,
                tags            = ["rate-limit", "bypass", "header"],
            )
            findings.append(f)
            self.log(f"Rate limit bypass: {url}", "FOUND")
        return findings

    # ── Mass Assignment ───────────────────────────────────────────────────

    async def _test_mass_assignment(self, target: str, endpoints: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        sensitive_fields = {
            "isAdmin": True, "is_admin": True, "role": "admin",
            "verified": True, "balance": 99999,
            "price": 0, "permissions": ["admin", "write"],
        }
        targets = [
            e for e in endpoints
            if any(k in e.lower() for k in ["user", "register", "profile", "account"])
        ][:3]

        for url in targets:
            body = {"username": "testuser", "email": "test@test.com"}
            body.update(sensitive_fields)
            resp = await self.engine.post(url, json=body)
            if not resp or resp.status not in (200, 201):
                continue
            accepted = [k for k in sensitive_fields if k.lower() in resp.body.lower()]
            if accepted:
                f = Finding(
                    vuln_type       = "Mass Assignment Vulnerability",
                    title           = "API Accepts Privileged Fields in POST Body",
                    endpoint        = url,
                    method          = "POST",
                    payload         = str({k: sensitive_fields[k] for k in accepted})[:300],
                    response_status = resp.status,
                    response_body   = resp.body[:500],
                    severity        = "HIGH",
                    cvss_score      = CVSS_PROFILES["MASS_ASSIGNMENT"]["score"],
                    cvss_vector     = CVSS_PROFILES["MASS_ASSIGNMENT"]["vector"],
                    owasp_category  = "API3:2023 - Broken Object Property Level Authorization",
                    description     = f"Fields {accepted} were accepted and reflected. Users may set their own admin roles or manipulate pricing.",
                    recommendation  = (
                        "1. Use explicit DTOs/serializers — never bind request body directly to ORM models.\n"
                        "2. Allowlist exactly which fields users may set.\n"
                        "3. Deny any unlisted properties by default."
                    ),
                    confirmed       = True,
                    module          = self.NAME,
                    tags            = ["mass-assignment", "authorization"],
                )
                findings.append(f)
                self.log(f"Mass assignment: {url} fields={accepted}", "FOUND")
        return findings

    # ── Sensitive Data ────────────────────────────────────────────────────

    async def _test_sensitive_data(self, endpoints: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        resps = await asyncio.gather(
            *[self.engine.get(u) for u in endpoints],
            return_exceptions=True
        )
        seen_patterns: set = set()

        for url, resp in zip(endpoints, resps):
            if isinstance(resp, Exception) or not resp or resp.status != 200 or len(resp.body) < 20:
                continue
            for pattern, label, severity in SENSITIVE_PATTERNS:
                if label in seen_patterns:
                    continue
                matches = re.findall(pattern, resp.body, re.IGNORECASE)
                if matches:
                    seen_patterns.add(label)
                    raw = str(matches[0])[:30]
                    masked = raw[:4] + "****" + raw[-4:] if len(raw) > 8 else "****"
                    f = Finding(
                        vuln_type       = f"Sensitive Data Exposure: {label}",
                        title           = f"API Response Contains {label}",
                        endpoint        = url,
                        method          = "GET",
                        response_status = resp.status,
                        response_body   = f"Pattern matched — sample: {masked}",
                        severity        = severity,
                        cvss_score      = CVSS_PROFILES["SENSITIVE_DATA"]["score"],
                        cvss_vector     = CVSS_PROFILES["SENSITIVE_DATA"]["vector"],
                        owasp_category  = "API3:2023 - Broken Object Property Level Authorization",
                        description     = f"{label} found in API response. Data minimization principle violated.",
                        recommendation  = f"Remove {label} from API responses. Apply data masking. Return only fields the client genuinely needs.",
                        confirmed       = True,
                        module          = self.NAME,
                        tags            = ["sensitive-data", "disclosure"],
                    )
                    findings.append(f)
                    self.log(f"Sensitive data ({label}): {url}", "FOUND")
        return findings

    # ── Debug Endpoints ───────────────────────────────────────────────────

    async def _test_debug_endpoints(self, target: str, result: ScanResult) -> List[Finding]:
        findings: List[Finding] = []
        debug_paths = [
            "/debug", "/console", "/env", "/.env", "/config",
            "/actuator/env", "/actuator/beans", "/actuator/mappings",
            "/actuator/dump", "/phpinfo.php", "/__debug__",
            "/api/debug", "/api/info", "/_debug", "/_admin",
        ]
        resps = await asyncio.gather(
            *[self.engine.get(target.rstrip("/") + p) for p in debug_paths],
            return_exceptions=True
        )
        env_re = re.compile(r"(DB_PASSWORD|SECRET_KEY|DATABASE_URL|AWS_SECRET|PRIVATE_KEY)", re.IGNORECASE)

        for path, resp in zip(debug_paths, resps):
            if isinstance(resp, Exception) or not resp:
                continue
            if resp.status == 200 and len(resp.body) > 50:
                env_match = env_re.search(resp.body)
                sev = "CRITICAL" if env_match else "HIGH"
                desc_extra = f" Contains environment variable: {env_match.group(1)}." if env_match else ""

                f = Finding(
                    vuln_type       = "Debug / Admin Endpoint Exposed",
                    title           = f"Debug Endpoint Accessible: {path}",
                    endpoint        = target.rstrip("/") + path,
                    method          = "GET",
                    response_status = resp.status,
                    response_body   = resp.body[:600],
                    severity        = sev,
                    cvss_score      = CVSS_PROFILES["DEBUG_ENV_VARS" if sev == "CRITICAL" else "DEBUG_ENDPOINT"]["score"],
                    cvss_vector     = CVSS_PROFILES["DEBUG_ENV_VARS" if sev == "CRITICAL" else "DEBUG_ENDPOINT"]["vector"],
                    owasp_category  = self.OWASP_CATEGORY,
                    description     = f"Debug endpoint '{path}' is accessible in production.{desc_extra}",
                    recommendation  = "Disable debug endpoints in production. If monitoring is needed, require authentication + IP allowlisting.",
                    confirmed       = True,
                    module          = self.NAME,
                    tags            = ["debug", "disclosure", "admin"],
                )
                findings.append(f)
                result.discovered_endpoints.append(target.rstrip("/") + path)
                self.log(f"Debug endpoint [{sev}]: {path}", "FOUND")
        return findings
