"""
modules/discovery.py — Async Endpoint Discovery
Probes common paths, parses OpenAPI/Swagger specs, extracts links.
OWASP API9:2023 - Improper Inventory Management
"""
from __future__ import annotations

import asyncio
import json
import re
from typing import List, Set
from urllib.parse import urljoin, urlparse

from core.plugins import BasePlugin
from core.models import Finding, ScanResult
from payloads.database import DISCOVERY_PATHS


class DiscoveryPlugin(BasePlugin):
    NAME           = "discovery"
    DESCRIPTION    = "Endpoint discovery: path probing, OpenAPI parsing, link extraction"
    OWASP_CATEGORY = "API9:2023 - Improper Inventory Management"
    TAGS           = ["discovery", "recon", "inventory", "swagger"]

    async def run(self, target: str, result: ScanResult) -> List[Finding]:
        self.log("Starting endpoint discovery")
        findings: List[Finding] = []
        discovered: Set[str] = set()

        # Run all discovery strategies concurrently
        path_urls, spec_urls, link_urls = await asyncio.gather(
            self._probe_common_paths(target),
            self._parse_api_spec(target),
            self._extract_links(target),
            return_exceptions=True,
        )

        for urls in (path_urls, spec_urls, link_urls):
            if isinstance(urls, set):
                discovered.update(urls)

        # Store results
        result.discovered_endpoints = list(discovered)
        result.scanned_urls.extend(list(discovered))

        # Report if API spec is public
        if isinstance(spec_urls, set) and spec_urls:
            f = Finding(
                vuln_type       = "API Specification Publicly Accessible",
                title           = "OpenAPI/Swagger Spec Exposed in Production",
                endpoint        = target,
                method          = "GET",
                payload         = "Spec file discovery",
                response_body   = f"Endpoints found: {list(spec_urls)[:10]}",
                severity        = "LOW",
                cvss_score      = 3.7,
                cvss_vector     = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                owasp_category  = self.OWASP_CATEGORY,
                description     = (
                    "The API specification (OpenAPI/Swagger) is publicly accessible, "
                    "revealing all endpoint paths, parameters, authentication schemes, and schemas. "
                    f"Discovered {len(spec_urls)} endpoints from spec."
                ),
                recommendation  = (
                    "1. Restrict spec access to authenticated developers in production.\n"
                    "2. If needed for public docs, serve a read-only subset.\n"
                    "3. Remove sensitive parameter examples from the spec."
                ),
                module          = self.NAME,
                tags            = ["discovery", "swagger", "openapi"],
            )
            findings.append(f)
            self.add(f)
            result.add_finding(f)

        self.log(f"Discovered {len(discovered)} endpoints total")
        return findings

    async def _probe_common_paths(self, target: str) -> Set[str]:
        """Concurrently probes all known API paths."""
        base = target.rstrip("/")
        urls = [base + p for p in DISCOVERY_PATHS]

        resps = await asyncio.gather(
            *[self.engine.get(u) for u in urls],
            return_exceptions=True
        )
        found: Set[str] = set()
        for url, resp in zip(urls, resps):
            if isinstance(resp, Exception) or not resp:
                continue
            if resp.status not in (404,) and len(resp.body) > 10:
                found.add(url)
        return found

    async def _parse_api_spec(self, target: str) -> Set[str]:
        """Downloads and parses OpenAPI/Swagger spec to extract all endpoints."""
        spec_paths = [
            "/swagger.json", "/openapi.json", "/swagger.yaml",
            "/openapi.yaml", "/api-docs", "/docs/swagger.json",
            "/api/swagger.json", "/v1/swagger.json", "/v2/swagger.json",
            "/api/v1/swagger.json",
        ]
        base = target.rstrip("/")

        resps = await asyncio.gather(
            *[self.engine.get(base + p) for p in spec_paths],
            return_exceptions=True
        )
        for path, resp in zip(spec_paths, resps):
            if isinstance(resp, Exception) or not resp or resp.status != 200:
                continue
            endpoints: Set[str] = set()

            # Try JSON parsing
            try:
                spec = resp.json()
                if spec:
                    for ep_path in spec.get("paths", {}).keys():
                        endpoints.add(base + ep_path)
                    if endpoints:
                        self.log(f"API spec at {path}: {len(endpoints)} endpoints")
                        return endpoints
            except Exception:
                pass

            # Try YAML regex extraction
            if "paths:" in resp.body:
                paths_found = re.findall(r'^\s{2}(/[^\s:]+):', resp.body, re.MULTILINE)
                for p in paths_found:
                    endpoints.add(base + p)
                if endpoints:
                    self.log(f"YAML spec at {path}: {len(endpoints)} endpoints")
                    return endpoints

        return set()

    async def _extract_links(self, target: str) -> Set[str]:
        """Extracts API-looking links from HTML/JS responses."""
        resp = await self.engine.get(target)
        if not resp or not resp.ok:
            return set()

        found: Set[str] = set()
        text = resp.body
        base = target.rstrip("/")

        # HTML href attributes
        for link in re.findall(r'href=["\']([^"\']+)["\']', text):
            if link.startswith("/"):
                found.add(base + link)

        # JSON/JS API paths
        for link in re.findall(r'["\'](/(?:api|v\d|auth|users|admin|graphql)[^"\'<>\s]{0,80})["\']', text):
            found.add(base + link)

        return found
