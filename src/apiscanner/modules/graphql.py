"""
modules/graphql.py — GraphQL Security Testing
OWASP API8:2023 - Security Misconfiguration / API4:2023 - Resource Consumption
"""
from __future__ import annotations

import asyncio
import json
import re
from typing import List, Optional

from core.plugins import BasePlugin
from core.models import Finding, ScanResult, CVSS_PROFILES
from payloads.database import GRAPHQL_PAYLOADS


class GraphQLPlugin(BasePlugin):
    NAME           = "graphql"
    DESCRIPTION    = "GraphQL: introspection, batching DoS, depth bombing, SSTI injection, field leakage"
    OWASP_CATEGORY = "API8:2023 - Security Misconfiguration"
    TAGS           = ["graphql", "introspection", "dos", "injection", "api"]

    async def run(self, target: str, result: ScanResult) -> List[Finding]:
        self.log("Starting GraphQL scan")
        findings: List[Finding] = []

        gql_url = await self._find_endpoint(target)
        if not gql_url:
            self.log("No GraphQL endpoint found — skipping")
            return findings

        self.log(f"GraphQL endpoint: {gql_url}")
        if gql_url not in result.discovered_endpoints:
            result.discovered_endpoints.append(gql_url)

        tasks = [
            self._test_introspection(gql_url),
            self._test_batching_dos(gql_url),
            self._test_depth_bomb(gql_url),
            self._test_field_suggestions(gql_url),
            self._test_injection(gql_url),
            self._test_alias_overloading(gql_url),
        ]
        all_results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in all_results:
            if isinstance(r, list):
                findings.extend(r)

        for f in findings:
            self.add(f)
            result.add_finding(f)

        self.log(f"Found {len(findings)} GraphQL issues")
        return findings

    # ── Helpers ───────────────────────────────────────────────────────────

    async def _gql(self, url: str, query: str, variables: dict = None):
        body = {"query": query}
        if variables:
            body["variables"] = variables
        return await self.engine.post(
            url, json=body, headers={"Content-Type": "application/json"}
        )

    async def _find_endpoint(self, target: str) -> Optional[str]:
        base = target.rstrip("/")
        probes = [
            self.engine.post(
                base + p,
                json={"query": "{ __typename }"},
                headers={"Content-Type": "application/json"},
            )
            for p in GRAPHQL_PAYLOADS["paths"]
        ]
        resps = await asyncio.gather(*probes, return_exceptions=True)
        for path, resp in zip(GRAPHQL_PAYLOADS["paths"], resps):
            if isinstance(resp, Exception) or not resp:
                continue
            if resp.status in (200, 400) and ('"data"' in resp.body or '"errors"' in resp.body):
                return base + path
        return None

    # ── Test: introspection ───────────────────────────────────────────────

    async def _test_introspection(self, url: str) -> List[Finding]:
        resp = await self._gql(url, GRAPHQL_PAYLOADS["introspection_simple"])
        if not resp or resp.status != 200:
            return []
        if '"__schema"' not in resp.body or '"types"' not in resp.body:
            return []

        type_names = re.findall(r'"name"\s*:\s*"([A-Za-z][A-Za-z0-9_]*)"', resp.body)
        user_types = [t for t in type_names if not t.startswith("__")][:15]

        f = Finding(
            vuln_type       = "GraphQL Introspection Enabled",
            title           = "GraphQL Introspection Active in Production",
            endpoint        = url,
            method          = "POST",
            payload         = '{"query":"{ __schema { types { name } } }"}',
            response_status = resp.status,
            response_body   = resp.body[:700],
            severity        = "MEDIUM",
            cvss_score      = CVSS_PROFILES["GQL_INTROSPECTION"]["score"],
            cvss_vector     = CVSS_PROFILES["GQL_INTROSPECTION"]["vector"],
            owasp_category  = self.OWASP_CATEGORY,
            description     = (
                f"GraphQL introspection is enabled, exposing the complete schema. "
                f"Attackers can enumerate all types, queries, mutations, field names, and arguments. "
                f"Discovered types: {user_types}. "
                f"This dramatically reduces effort needed to attack the API."
            ),
            recommendation  = (
                "1. Disable introspection in production.\n"
                "   Apollo: `introspection: process.env.NODE_ENV !== 'production'`\n"
                "   Strawberry: add `extensions=[DisableIntrospection()]`\n"
                "2. Implement query depth and complexity limits.\n"
                "3. Use query allowlisting (persisted queries) for public APIs.\n"
                "4. Log all introspection attempts as security events."
            ),
            references      = [
                "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL",
            ],
            confirmed       = True,
            module          = self.NAME,
            tags            = ["graphql", "introspection", "information-disclosure"],
        )
        self.log(f"Introspection enabled: {url}", "FOUND")
        return [f]

    # ── Test: batching DoS ────────────────────────────────────────────────

    async def _test_batching_dos(self, url: str) -> List[Finding]:
        batch = [{"query": "{ __typename }"}] * 50
        resp = await self.engine.post(url, json=batch,
                                      headers={"Content-Type": "application/json"})
        if not resp or resp.status != 200:
            return []

        try:
            data = resp.json()
        except Exception:
            return []

        if not isinstance(data, list) or len(data) < 2:
            return []

        f = Finding(
            vuln_type       = "GraphQL Unlimited Query Batching",
            title           = "GraphQL Allows Unlimited Batching — DoS Risk",
            endpoint        = url,
            method          = "POST",
            payload         = "Array of 50 queries: [{query:__typename}] × 50",
            response_status = resp.status,
            response_body   = resp.body[:400],
            severity        = "MEDIUM",
            cvss_score      = CVSS_PROFILES["GQL_DOS"]["score"],
            cvss_vector     = CVSS_PROFILES["GQL_DOS"]["vector"],
            owasp_category  = "API4:2023 - Unrestricted Resource Consumption",
            description     = (
                "GraphQL batching is enabled without limits. A single HTTP request "
                "containing 50 queries was processed successfully. Attackers can "
                "send thousands of queries per request, bypassing rate limits and "
                "causing server resource exhaustion."
            ),
            recommendation  = (
                "1. Limit batch size to ≤5-10 queries per request.\n"
                "2. Implement query cost analysis (query complexity limits).\n"
                "3. Set query depth limits (recommend max 7 levels).\n"
                "4. Rate limit by total query count, not HTTP request count."
            ),
            confirmed       = True,
            module          = self.NAME,
            tags            = ["graphql", "batching", "dos"],
        )
        self.log(f"Batching DoS: {url}", "FOUND")
        return [f]

    # ── Test: depth bomb ──────────────────────────────────────────────────

    async def _test_depth_bomb(self, url: str) -> List[Finding]:
        resp = await self._gql(url, GRAPHQL_PAYLOADS["depth_bomb"])
        if not resp or resp.status != 200:
            return []

        # If resolved (not rejected with depth error), it's vulnerable
        if '"data"' in resp.body and "depth" not in resp.body.lower() and "limit" not in resp.body.lower():
            f = Finding(
                vuln_type       = "GraphQL No Query Depth Limit",
                title           = "GraphQL Processes Deeply Nested Queries (DoS Risk)",
                endpoint        = url,
                method          = "POST",
                payload         = GRAPHQL_PAYLOADS["depth_bomb"][:200],
                response_status = resp.status,
                response_body   = resp.body[:400],
                severity        = "MEDIUM",
                cvss_score      = CVSS_PROFILES["GQL_DOS"]["score"],
                cvss_vector     = CVSS_PROFILES["GQL_DOS"]["vector"],
                owasp_category  = "API4:2023 - Unrestricted Resource Consumption",
                description     = (
                    "A 12-level deeply nested query was accepted without rejection. "
                    "Deeply nested queries cause exponential resource consumption in resolvers."
                ),
                recommendation  = (
                    "Implement query depth limiting (max 7–10 levels). "
                    "Use graphql-depth-limit or graphql-query-complexity."
                ),
                confirmed       = True,
                module          = self.NAME,
                tags            = ["graphql", "depth", "dos"],
            )
            self.log(f"Depth bomb not blocked: {url}", "FOUND")
            return [f]
        return []

    # ── Test: field suggestions ───────────────────────────────────────────

    async def _test_field_suggestions(self, url: str) -> List[Finding]:
        resp = await self._gql(url, GRAPHQL_PAYLOADS["field_suggestion"])
        if not resp:
            return []

        if "Did you mean" in resp.body or "did you mean" in resp.body:
            suggested = re.search(r'Did you mean[^"]*"([^"]+)"', resp.body)
            field_name = suggested.group(1) if suggested else "unknown"

            f = Finding(
                vuln_type       = "GraphQL Field Name Disclosure via Suggestions",
                title           = "GraphQL Suggests Valid Field Names on Typos",
                endpoint        = url,
                method          = "POST",
                payload         = '{"query": "{ usr { id } }"}',
                response_status = resp.status,
                response_body   = resp.body[:400],
                severity        = "LOW",
                cvss_score      = 3.1,
                cvss_vector     = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                owasp_category  = self.OWASP_CATEGORY,
                description     = (
                    f"GraphQL returns 'Did you mean {field_name}?' on field typos, "
                    f"enabling schema enumeration even without introspection access."
                ),
                recommendation  = (
                    "Disable field suggestions in production. "
                    "Apollo Server: disable via custom error masking plugin."
                ),
                confirmed       = True,
                module          = self.NAME,
                tags            = ["graphql", "enumeration", "info"],
            )
            self.log(f"Field suggestions exposed: {url}", "FOUND")
            return [f]
        return []

    # ── Test: injection via arguments ─────────────────────────────────────

    async def _test_injection(self, url: str) -> List[Finding]:
        sqli_re = re.compile(
            r"(SQL syntax|mysql_|ORA-|SQLSTATE|syntax error)", re.IGNORECASE
        )
        injection_queries = [
            '{ user(id: "1 OR 1=1") { id name email } }',
            "{ users(filter: \"1'; DROP TABLE users--\") { id } }",
            '{ search(q: "<script>alert(1)</script>") { results } }',
        ]
        tasks = [self._gql(url, q) for q in injection_queries]
        resps = await asyncio.gather(*tasks, return_exceptions=True)

        for query, resp in zip(injection_queries, resps):
            if isinstance(resp, Exception) or not resp:
                continue
            if sqli_re.search(resp.body) or ("<script>" in query and "<script>" in resp.body):
                f = Finding(
                    vuln_type       = "Injection via GraphQL Arguments",
                    title           = "Injection (SQLi/XSS) Through GraphQL Arguments",
                    endpoint        = url,
                    method          = "POST",
                    payload         = json.dumps({"query": query})[:200],
                    response_status = resp.status,
                    response_body   = resp.body[:500],
                    severity        = "CRITICAL",
                    cvss_score      = CVSS_PROFILES["GQL_INJECTION"]["score"],
                    cvss_vector     = CVSS_PROFILES["GQL_INJECTION"]["vector"],
                    owasp_category  = "A03:2021 - Injection",
                    description     = "SQL error or XSS reflection returned through GraphQL arguments — resolvers are passing arguments unsanitized to databases/templates.",
                    recommendation  = "Sanitize all GraphQL resolver arguments. Use ORM with parameterized queries in every resolver.",
                    confirmed       = True,
                    module          = self.NAME,
                    tags            = ["graphql", "injection", "sqli"],
                )
                self.log(f"GraphQL injection: {url}", "FOUND")
                return [f]
        return []

    # ── Test: alias overloading ───────────────────────────────────────────

    async def _test_alias_overloading(self, url: str) -> List[Finding]:
        """Alias-based DoS — bypasses rate limiting via aliases in one query."""
        aliases = "\n".join(f"q{i}: __typename" for i in range(100))
        query = "{ " + aliases + " }"
        resp = await self._gql(url, query)
        if not resp or resp.status != 200:
            return []

        # Count how many aliases were resolved
        count = resp.body.count('"__typename"')
        if count >= 50:
            f = Finding(
                vuln_type       = "GraphQL Alias Overloading (DoS)",
                title           = "GraphQL Alias Overloading — Rate Limit Bypass",
                endpoint        = url,
                method          = "POST",
                payload         = f"100 aliased fields in one query (resolved: {count})",
                response_status = resp.status,
                response_body   = resp.body[:300],
                severity        = "MEDIUM",
                cvss_score      = CVSS_PROFILES["GQL_DOS"]["score"],
                cvss_vector     = CVSS_PROFILES["GQL_DOS"]["vector"],
                owasp_category  = "API4:2023 - Unrestricted Resource Consumption",
                description     = (
                    f"100 aliased fields in one query resolved {count} times. "
                    "Aliases allow multiplying query execution without additional HTTP requests, "
                    "effectively bypassing rate limiting."
                ),
                recommendation  = (
                    "Implement query cost/complexity analysis that counts aliased fields. "
                    "Limit maximum aliases per query."
                ),
                confirmed       = True,
                module          = self.NAME,
                tags            = ["graphql", "alias", "dos", "rate-limit-bypass"],
            )
            self.log(f"Alias overloading: {url} ({count} resolved)", "FOUND")
            return [f]
        return []
