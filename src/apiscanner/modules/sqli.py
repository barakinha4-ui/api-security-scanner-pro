"""
modules/sqli.py — SQL Injection + NoSQL Injection
OWASP A03:2021 - Injection
"""
from __future__ import annotations

import re
import time
import asyncio
from typing import List
from urllib.parse import quote

from core.plugins import BasePlugin
from core.models import Finding, ScanResult, CVSS_PROFILES
from payloads.database import SQLI, NOSQLI, PayloadMutator


class SQLiPlugin(BasePlugin):
    NAME           = "sqli"
    DESCRIPTION    = "SQL Injection (error-based, blind time-based) + NoSQL Injection"
    OWASP_CATEGORY = "A03:2021 - Injection"
    TAGS           = ["sqli", "nosqli", "injection", "database", "critical"]

    _ERROR_RE = re.compile("|".join(SQLI["error_patterns"]), re.IGNORECASE)
    _NOSQL_RE = re.compile("|".join(NOSQLI["error_patterns"]), re.IGNORECASE)

    # Parameters to fuzz
    _PARAMS = ["id", "q", "search", "user", "username", "email",
               "name", "page", "sort", "filter", "category", "type",
               "product_id", "user_id", "order_id", "item"]

    async def run(self, target: str, result: ScanResult) -> List[Finding]:
        self.log("Starting SQL/NoSQL injection scan")
        findings: List[Finding] = []

        endpoints = result.discovered_endpoints or [target]

        tasks = []
        for url in endpoints:
            tasks.append(self._test_error_sqli(url))
            tasks.append(self._test_blind_sqli(url))
            tasks.append(self._test_post_sqli(url))
            tasks.append(self._test_nosql(url))

        all_results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in all_results:
            if isinstance(r, list):
                findings.extend(r)

        for f in findings:
            self.add(f)
            result.add_finding(f)

        self.log(f"Found {len(findings)} SQL/NoSQL issues")
        return findings

    async def _test_error_sqli(self, url: str) -> List[Finding]:
        findings: List[Finding] = []
        payloads = SQLI["error_based"][:8]

        # Build a batch of concurrent requests
        tasks = []
        combos = []
        for param in self._PARAMS[:6]:
            for payload in payloads[:5]:
                for variant in PayloadMutator.mutate(payload, ["url", "comment"])[:2]:
                    test_url = f"{url}?{param}={quote(variant, safe='')}"
                    combos.append((param, payload, variant, test_url))
                    tasks.append(self.engine.get(test_url))

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        seen_urls: set = set()
        for (param, original_payload, variant, test_url), resp in zip(combos, responses):
            if isinstance(resp, Exception) or not resp or url in seen_urls:
                continue
            if self._ERROR_RE.search(resp.body):
                seen_urls.add(url)
                cvss = CVSS_PROFILES["SQLI"]
                f = Finding(
                    vuln_type    = "SQL Injection (Error-Based)",
                    title        = "Error-Based SQL Injection Detected",
                    endpoint     = url,
                    method       = "GET",
                    parameter    = param,
                    payload      = original_payload,
                    response_status = resp.status,
                    response_body   = resp.body[:800],
                    response_headers= resp.headers,
                    response_time_ms= resp.elapsed_ms,
                    severity        = "CRITICAL",
                    cvss_score      = cvss["score"],
                    cvss_vector     = cvss["vector"],
                    owasp_category  = self.OWASP_CATEGORY,
                    description     = (
                        f"SQL error messages were returned when injecting '{original_payload}' "
                        f"into parameter '{param}'. The server is building SQL queries by "
                        f"directly concatenating user input, enabling arbitrary database access."
                    ),
                    recommendation  = (
                        "1. Use parameterized queries / prepared statements for ALL database ops.\n"
                        "2. Apply an ORM (SQLAlchemy, Hibernate, TypeORM) that auto-escapes input.\n"
                        "3. Validate and sanitize all inputs with strict allowlists.\n"
                        "4. Disable verbose database errors in production.\n"
                        "5. Apply least-privilege to the database account."
                    ),
                    references      = [
                        "https://owasp.org/www-community/attacks/SQL_Injection",
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                    ],
                    confirmed       = True,
                    module          = self.NAME,
                    tags            = ["sqli", "error-based"],
                )
                findings.append(f)
                self.log(f"SQLi confirmed: {url} param={param}", "FOUND")
        return findings

    async def _test_blind_sqli(self, url: str) -> List[Finding]:
        """Time-based blind SQL injection — measures response delay delta."""
        findings: List[Finding] = []

        for param in ["id", "user_id", "product_id"][:2]:
            baseline_resp = await self.engine.get(f"{url}?{param}=1")
            if not baseline_resp:
                continue

            payload = "1' AND SLEEP(3)--"
            t0 = time.perf_counter()
            resp = await self.engine.get(f"{url}?{param}={quote(payload, safe='')}")
            elapsed = (time.perf_counter() - t0) * 1000

            if elapsed > 2800 and resp.ok:
                cvss = CVSS_PROFILES["SQLI"]
                f = Finding(
                    vuln_type       = "SQL Injection (Blind Time-Based)",
                    title           = "Time-Based Blind SQL Injection Detected",
                    endpoint        = url,
                    method          = "GET",
                    parameter       = param,
                    payload         = payload,
                    response_status = resp.status,
                    response_body   = f"Delay: {elapsed:.0f}ms (SLEEP(3) injected)",
                    response_time_ms= elapsed,
                    severity        = "CRITICAL",
                    cvss_score      = CVSS_PROFILES["SQLI"]["score"],
                    cvss_vector     = CVSS_PROFILES["SQLI"]["vector"],
                    owasp_category  = self.OWASP_CATEGORY,
                    description     = (
                        f"SLEEP(3) injection caused a {elapsed:.0f}ms delay, confirming "
                        f"blind SQL injection in parameter '{param}'. No error messages "
                        f"are visible, but database commands are being executed."
                    ),
                    recommendation  = "Use parameterized queries. Even without visible errors, user input is passed unsanitized to the database.",
                    confirmed       = True,
                    module          = self.NAME,
                    tags            = ["sqli", "blind", "time-based"],
                )
                findings.append(f)
                self.log(f"Blind SQLi: {url} delay={elapsed:.0f}ms", "FOUND")
        return findings

    async def _test_post_sqli(self, url: str) -> List[Finding]:
        """Tests POST body fields for SQL injection."""
        findings: List[Finding] = []
        payload = "' OR '1'='1"

        bodies = [
            {"username": payload, "password": "test"},
            {"email": payload},
            {"search": payload},
        ]
        resps = await asyncio.gather(
            *[self.engine.post(url, json=b) for b in bodies],
            return_exceptions=True
        )

        for body, resp in zip(bodies, resps):
            if isinstance(resp, Exception) or not resp:
                continue
            if self._ERROR_RE.search(resp.body):
                key = list(body.keys())[0]
                f = Finding(
                    vuln_type       = "SQL Injection (POST Body)",
                    title           = f"SQL Injection in POST Field '{key}'",
                    endpoint        = url,
                    method          = "POST",
                    parameter       = key,
                    payload         = str(body),
                    response_status = resp.status,
                    response_body   = resp.body[:600],
                    severity        = "CRITICAL",
                    cvss_score      = CVSS_PROFILES["SQLI"]["score"],
                    cvss_vector     = CVSS_PROFILES["SQLI"]["vector"],
                    owasp_category  = self.OWASP_CATEGORY,
                    description     = f"SQL error in POST body field '{key}'.",
                    recommendation  = "Sanitize all POST body fields with parameterized queries.",
                    confirmed       = True,
                    module          = self.NAME,
                    tags            = ["sqli", "post"],
                )
                findings.append(f)
                self.log(f"POST SQLi: {url} field={key}", "FOUND")
                break
        return findings

    async def _test_nosql(self, url: str) -> List[Finding]:
        """Tests NoSQL injection via operator injection in GET params and POST body."""
        findings: List[Finding] = []

        # 1. URL param injection
        for payload in NOSQLI["url_params"][:3]:
            test_url = f"{url}?username{payload}&password{payload}"
            resp = await self.engine.get(test_url)
            if resp and self._NOSQL_RE.search(resp.body):
                findings.append(self._nosql_finding(url, payload, "GET param"))
                self.log(f"NoSQLi (GET): {url}", "FOUND")
                return findings

        # 2. JSON body operator injection
        bodies = [
            {"username": {"$ne": None}, "password": {"$ne": None}},
            {"username": {"$gt": ""}, "password": {"$gt": ""}},
            {"username": {"$regex": ".*"}},
        ]
        resps = await asyncio.gather(
            *[self.engine.post(url, json=b) for b in bodies],
            return_exceptions=True
        )
        for body, resp in zip(bodies, resps):
            if isinstance(resp, Exception) or not resp:
                continue
            # Successful login (200 + token in body) after operator injection = confirmed
            success = (resp.status == 200 and
                       any(kw in resp.body.lower()
                           for kw in ["token", "access_token", "session", '"id"']))
            if success or self._NOSQL_RE.search(resp.body):
                findings.append(self._nosql_finding(url, str(body), "POST JSON body"))
                self.log(f"NoSQLi (POST): {url}", "FOUND")
                break

        return findings

    def _nosql_finding(self, url, payload, location) -> Finding:
        return Finding(
            vuln_type       = "NoSQL Injection",
            title           = "NoSQL Operator Injection (MongoDB)",
            endpoint        = url,
            method          = "POST" if "body" in location else "GET",
            parameter       = location,
            payload         = str(payload)[:200],
            severity        = "CRITICAL",
            cvss_score      = CVSS_PROFILES["NOSQLI"]["score"],
            cvss_vector     = CVSS_PROFILES["NOSQLI"]["vector"],
            owasp_category  = self.OWASP_CATEGORY,
            description     = (
                f"MongoDB operator injection via {location}. Operators like $ne, $gt, $regex "
                f"allow bypassing authentication and extracting data without valid credentials."
            ),
            recommendation  = (
                "1. Sanitize inputs — strip/reject MongoDB operators ($ne, $gt, $where, etc.).\n"
                "2. Use strict schema validation (Mongoose strict mode).\n"
                "3. Disable the $where operator globally in MongoDB.\n"
                "4. Apply allowlist validation for all query parameters."
            ),
            references      = ["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"],
            confirmed       = True,
            module          = self.NAME,
            tags            = ["nosqli", "mongodb", "injection"],
        )
