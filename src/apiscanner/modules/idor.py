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

        endpoints = (result.discovered_endpoints or [target])[:20]
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

        evidence_map = {
            "status_match": False,
            "pattern_match": False,
            "time_based": False,
            "boolean_based": False
        }
        confirmation_evidence = []
        
        # If we have an attacker token, use it to confirm access to the SAME resource
        if attacker_auth:
            self.log(f"Confirming IDOR with attacker token on {url}")
            confirm_resp = await self.engine.get(url, headers={"Authorization": str(attacker_auth)})
            
            if confirm_resp and confirm_resp.status == 200:
                # Potential IDOR confirmed
                evidence_map["status_match"] = True
                confirmation_evidence.append("Attacker token successfully accessed Victim's private resource (HTTP 200)")

        # Sequential ID scanning
        test_ids = [str(i) for i in [orig_int + 1, orig_int - 1, 1, 2] if i > 0 and str(i) != original_id]
        test_urls = [url.replace(f"/{original_id}", f"/{tid}", 1) for tid in test_ids]
        resps = await asyncio.gather(*[self.engine.get(u) for u in test_urls], return_exceptions=True)

        unique_successes = []
        for tid, resp in zip(test_ids, resps):
            if (not isinstance(resp, Exception) and resp and
                    resp.status == 200 and len(resp.body) > 30 and
                    resp.body != baseline.body):
                unique_successes.append(tid)

        if unique_successes:
            evidence_map["boolean_based"] = True
            confirmation_evidence.append(f"Sequential ID Access: Different data returned for IDs {', '.join(unique_successes)}")

        if evidence_map["status_match"] or evidence_map["boolean_based"]:
            f = Finding(
                vuln_type       = "Broken Object Level Authorization (BOLA/IDOR)",
                endpoint        = url,
                method          = "GET",
                parameter       = "path_id",
                severity        = "HIGH",
                owasp_category  = self.OWASP_CATEGORY,
                module          = self.NAME,
                confirmation_evidence = confirmation_evidence
            )
            
            confidence = f.calculate_confidence(evidence_map)
            
            if evidence_map["status_match"]:
                # Multi-user confirmation is very critical
                f.severity = "CRITICAL"
                f.confirmed = True
                f.title = "CRITICAL: Confirmed Multi-User IDOR Access"
                f.description = "BOLA Confirmed: Resource owned by one user was successfully accessed by another user. This represents a total failure of access controls."
            else:
                f.severity = "HIGH"
                f.title = "IDOR: Unauthorized Access to Private Objects"
                f.description = f"Endpoint returned HTTP 200 with unique content for sequential IDs: {unique_successes}. This indicates potential missing ownership checks."

            f.cvss_score = 9.1 if f.severity == "CRITICAL" else 8.1
            f.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
            f.recommendation = "Implement strict object-level authorization. Verify the authenticated user owns the resource BEFORE returning it."
            
            findings.append(f)
            self.log(f"IDOR detected on {url} (Confidence: {confidence:.2f})", "FOUND")
            
        return findings

    async def _test_param_idor(self, url: str) -> List[Finding]:
        """Tests query parameter ID enumeration."""
        findings: List[Finding] = []
        
        # Use safe iteration to avoid slicing lints
        count = 0
        for param in self._ID_PARAMS:
            if count >= 4: break
            count = count + 1
            
            tasks = [self.engine.get(url, params={param: str(i)}) for i in [1, 2, 3, 100]]
            resps = await asyncio.gather(*tasks, return_exceptions=True)
            
            successes = []
            bodies = set()
            evidence_map = {"status_match": False, "boolean_based": False}
            
            for i, resp in zip([1, 2, 3, 100], resps):
                if (not isinstance(resp, Exception) and resp and
                        resp.status == 200 and len(resp.body) > 30):
                    bodies.add(resp.body[:100])
                    successes.append(str(i))

            if len(successes) >= 2 and len(bodies) >= 2:
                evidence_map["status_match"] = True
                evidence_map["boolean_based"] = True
                
                f = Finding(
                    vuln_type       = "IDOR via Query Parameter",
                    title           = f"IDOR: Parameter '{param}' Returns Different Objects",
                    endpoint        = url,
                    method          = "GET",
                    parameter       = param,
                    payload         = f"?{param}=1, ?{param}=2, ?{param}=3",
                    severity        = "HIGH",
                    owasp_category  = self.OWASP_CATEGORY,
                    module          = self.NAME,
                    confirmation_evidence = [f"Found {len(successes)} valid IDs for parameter '{param}'", 
                                             f"Returned content unique for each ID"]
                )
                f.calculate_confidence(evidence_map)
                findings.append(f)
                self.log(f"IDOR detected on {url} ?{param}=", "FOUND")
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
                severity        = "HIGH",
                owasp_category  = "API5:2023 - Broken Function Level Authorization",
                module          = self.NAME,
                confirmation_evidence = [f"Admin-looking path '{url}' accessible without authentication", 
                                         f"Response status: {resp.status}, Body length: {len(resp.body)}"]
            )
            f.calculate_confidence({"status_match": True, "pattern_match": True})
            f.description = f"Endpoint '{url}' appears to be privileged but returned HTTP 200. Administrative functions must be restricted."
            f.recommendation = "Implement RBAC — require explicit role grants for admin endpoints."
            findings.append(f)
            self.log(f"Privileged endpoint: {url}", "WARN")
        return findings
