"""
modules/idor.py — IDOR + Broken Function Level Authorization
OWASP API1:2023 / API5:2023
"""
from __future__ import annotations

import re
import asyncio
from typing import List, Optional
from core.plugins import BasePlugin
from core.models import Finding, ScanResult, CVSS_PROFILES


class IDORPlugin(BasePlugin):
    NAME           = "idor"
    DESCRIPTION    = "IDOR (numeric/UUID IDs), BFLA (admin endpoint access), param enumeration"
    OWASP_CATEGORY = "API1:2023 - Broken Object Level Authorization"
    TAGS           = ["idor", "bfla", "authorization", "access-control"]

    _ID_IN_PATH  = re.compile(r'/(\d{1,10})(?:/|$|\?|#)')
    _UUID_IN_PATH = re.compile(r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})')
    _ID_PARAMS   = ["id", "user_id", "account_id", "record_id", "item_id",
                    "order_id", "doc_id", "file_id", "post_id", "product_id"]

    async def run(self, target: str, result: ScanResult) -> List[Finding]:
        self.log("Starting IDOR / BFLA scan")
        findings: List[Finding] = []

        endpoints = result.discovered_endpoints or [target]
        tasks = [self._test_path_idor(url) for url in endpoints]
        tasks += [self._test_param_idor(url) for url in endpoints]
        tasks += [self._test_bfla(url) for url in endpoints]

        all_results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in all_results:
            if isinstance(r, list):
                findings.extend(r)

        for f in findings:
            self.add(f)
            result.add_finding(f)

        self.log(f"Found {len(findings)} IDOR/BFLA issues")
        return findings

    async def _test_path_idor(self, url: str) -> List[Finding]:
        """
        Iterates numeric IDs and confirms IDOR using a second auth token (attacker)
        if available. This is the 'Gold Standard' for IDOR detection.
        """
        findings: List[Finding] = []
        attacker_auth = self.config.get("auth_attacker")

        m = self._ID_IN_PATH.search(url)
        if not m:
            return findings

        original_id = m.group(1)
        try:
            orig_int = int(original_id)
        except ValueError:
            return findings

        # Baseline request (Victim account)
        baseline = await self.engine.get(url)
        if not baseline or baseline.status != 200:
            return findings

        test_ids = [str(i) for i in [orig_int + 1, orig_int - 1, 1, 2] if i > 0 and str(i) != original_id]
        
        # If we have an attacker token, use it to confirm access to the SAME resource
        if attacker_auth:
            self.log(f"Confirming IDOR with attacker token on {url}")
            # Attacker tries to access the Victim's resource
            confirm_resp = await self.engine.get(url, headers={"Authorization": attacker_auth})
            
            if confirm_resp and confirm_resp.status == 200:
                # Potential IDOR confirmed - Attacker accessed Victim's data
                f = Finding(
                    vuln_type       = "IDOR (Confirmed Multi-User)",
                    title           = "Confirmed IDOR: Unauthorized Access to Private Resource",
                    endpoint        = url,
                    method          = "GET",
                    parameter       = "path_id",
                    payload         = f"Attacker Token used to access {url}",
                    response_status = confirm_resp.status,
                    severity        = "CRITICAL",
                    cvss_score      = 9.1,
                    cvss_vector     = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    owasp_category  = self.OWASP_CATEGORY,
                    confirmed       = True,
                    module          = self.NAME,
                    tags            = ["idor", "multi-user", "confirmed"],
                    description     = (
                        f"CRITICAL: Resource owned by one user was successfully accessed by another user "
                        f"using a different authentication token. This confirms a total breakdown of "
                        f"Broken Object Level Authorization (BOLA)."
                    ),
                    recommendation  = "Implement strict server-side ownership checks. Verify the authenticated user owns the object ID 123 before returning data.",
                )
                findings.append(f)
                self.log(f"IDOR CONFIRMED (Multi-User) on {url}", "FOUND")
                return findings # Found a critical one, move on to next endpoint

        # Fallback to sequential ID scanning if no attacker token or if first test didn't yield critical
        test_urls = [url.replace(f"/{original_id}", f"/{tid}", 1) for tid in test_ids]
        resps = await asyncio.gather(*[self.engine.get(u) for u in test_urls], return_exceptions=True)

        successes = []
        for tid, resp in zip(test_ids, resps):
            if (not isinstance(resp, Exception) and resp and
                    resp.status == 200 and len(resp.body) > 30 and
                    resp.body != baseline.body):
                successes.append(tid)

        if successes:
            f = Finding(
                vuln_type       = "IDOR — Insecure Direct Object Reference",
                title           = "Possible IDOR: Sequential IDs Expose Unique Data",
                endpoint        = url,
                method          = "GET",
                parameter       = "path_id",
                payload         = f"Tested IDs: {successes[:3]}",
                severity        = "HIGH",
                cvss_score      = CVSS_PROFILES["IDOR"]["score"],
                cvss_vector     = CVSS_PROFILES["IDOR"]["vector"],
                owasp_category  = self.OWASP_CATEGORY,
                confirmed       = False, # Unconfirmed without 2nd token
                module          = self.NAME,
                tags            = ["idor", "sequential-ids"],
                description     = f"Endpoint returns HTTP 200 with unique content for IDs: {successes}.",
                recommendation  = "Implement per-object authorization checks.",
            )
            findings.append(f)
            self.log(f"Possible IDOR: {url}", "WARN")
            
        return findings

    async def _test_param_idor(self, url: str) -> List[Finding]:
        """Tests query parameter ID enumeration."""
        findings: List[Finding] = []

        # Only test first 4 common ID parameters to save time
        for param in self._ID_PARAMS[:4]:
            tasks = [self.engine.get(url, params={param: str(i)}) for i in [1, 2, 3, 100]]
            resps = await asyncio.gather(*tasks, return_exceptions=True)
            
            successes = []
            bodies = set()
            
            for i, resp in zip([1, 2, 3, 100], resps):
                if (not isinstance(resp, Exception) and resp and
                        resp.status == 200 and len(resp.body) > 30):
                    bodies.add(resp.body[:100])
                    successes.append(str(i))

            if len(successes) >= 2 and len(bodies) >= 2:
                f = Finding(
                    vuln_type       = "IDOR via Query Parameter",
                    title           = f"IDOR: Parameter '{param}' Returns Different Objects",
                    endpoint        = url,
                    method          = "GET",
                    parameter       = param,
                    payload         = f"?{param}=1, ?{param}=2, ?{param}=3",
                    severity        = "HIGH",
                    cvss_score      = CVSS_PROFILES["IDOR"]["score"],
                    cvss_vector     = CVSS_PROFILES["IDOR"]["vector"],
                    owasp_category  = self.OWASP_CATEGORY,
                    description     = f"Parameter '{param}' accepts arbitrary IDs and returns different data for each, suggesting missing per-object authorization.",
                    recommendation  = "Validate that the authenticated user has permission to access the specific resource ID in every request.",
                    confirmed       = False,
                    module          = self.NAME,
                    tags            = ["idor", "parameter-enumeration"],
                )
                findings.append(f)
                self.log(f"Possible IDOR param: {url} ?{param}=", "WARN")
                break
        return findings

    async def _test_bfla(self, url: str) -> List[Finding]:
        """Tests Broken Function Level Authorization — admin endpoints without elevated roles."""
        findings: List[Finding] = []

        admin_keywords = ["admin", "manage", "internal", "private", "secret",
                          "config", "control", "root", "superuser", "staff"]
        if not any(kw in url.lower() for kw in admin_keywords):
            return findings

        resp = await self.engine.get(url)
        if resp and resp.status == 200 and len(resp.body) > 50:
            f = Finding(
                vuln_type       = "Broken Function Level Authorization (BFLA)",
                title           = "Privileged Endpoint Accessible Without Admin Role",
                endpoint        = url,
                method          = "GET",
                payload         = "",
                response_status = resp.status,
                response_body   = resp.body[:500],
                severity        = "HIGH",
                cvss_score      = CVSS_PROFILES["BFLA"]["score"],
                cvss_vector     = CVSS_PROFILES["BFLA"]["vector"],
                owasp_category  = "API5:2023 - Broken Function Level Authorization",
                description     = (
                    f"Endpoint '{url}' appears to be privileged (contains admin/manage/internal) "
                    f"but returned HTTP 200 with content. Administrative functions must be "
                    f"restricted to authorized roles."
                ),
                recommendation  = (
                    "1. Implement RBAC — require explicit role grants for admin endpoints.\n"
                    "2. Default-deny: all endpoints require authentication/authorization.\n"
                    "3. Separate admin APIs to a separate subdomain/port not exposed publicly.\n"
                    "4. Log all access attempts to privileged endpoints."
                ),
                confirmed       = False,
                module          = self.NAME,
                tags            = ["bfla", "admin", "authorization"],
            )
            findings.append(f)
            self.log(f"Privileged endpoint: {url}", "WARN")
        return findings
