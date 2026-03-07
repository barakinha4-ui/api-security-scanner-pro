"""
core/engine.py — Advanced Async HTTP Engine with SSRF Protection & Rate Limiting
"""
from __future__ import annotations

import asyncio
import random
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse
import ipaddress

import httpx
from core.logger import logger

# ─── Constants ───────────────────────────────────────────────────────────────

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "PostmanRuntime/7.36.1",
    "curl/8.6.0",
]

_SENSITIVE_HEADERS = {"authorization", "cookie", "x-api-key", "token", "session"}
_SENSITIVE_PATTERNS = [
    re.compile(r"Bearer\s+[a-zA-Z0-9\-\._~+/]+=*", re.I),
    re.compile(r"ey[a-zA-Z0-9+_=\-\.]+", re.I), # JWT
]

# ─── Response Wrapper ─────────────────────────────────────────────────────────

@dataclass
class Response:
    """Unified response object."""
    url:          str
    method:       str
    status:       int             = 0
    headers:      Dict[str, str]  = field(default_factory=dict)
    body:         str             = ""
    elapsed_ms:   float           = 0.0
    error:        Optional[str]   = None

    @property
    def ok(self) -> bool:
        return self.error is None and 0 < self.status < 400

    @property
    def headers_lower(self) -> Dict[str, str]:
        return {k.lower(): v for k, v in self.headers.items()}

    def json(self) -> Any:
        import json
        try:
            return json.loads(self.body)
        except Exception:
            return None

# ─── Async HTTP Engine ────────────────────────────────────────────────────────

class AsyncEngine:
    """
    Native Async HTTP engine built on httpx with security guardrails.
    """

    def __init__(
        self,
        *,
        concurrency:  int   = 20,
        timeout:      int   = 10,
        delay:        float = 0.2,
        stealth:      bool  = False,
        verify_ssl:   bool  = True,
        headers:      Optional[Dict[str, str]] = None,
        proxy:        Optional[str] = None,
        dry_run:      bool  = False,
        allow_internal: bool = False, # SSRF Protection Toggle
    ):
        self.concurrency   = concurrency
        self.timeout       = timeout
        self.base_delay    = delay
        self.stealth       = stealth
        self.verify_ssl    = verify_ssl
        self.base_headers  = headers or {}
        self.proxy         = proxy
        self.dry_run       = dry_run
        self.allow_internal = allow_internal

        from scanner_config import ScannerConfig
        _cfg = ScannerConfig()
        self.rate_limit_per_minute = _cfg.rate_limit_per_minute
        self.allow_internal = allow_internal or _cfg.allow_private_targets
        
        self._rate_limits: Dict[str, int] = {}
        self._rate_limit_start: Dict[str, float] = {}

        self._client:      Optional[httpx.AsyncClient] = None
        self._semaphore    = asyncio.Semaphore(concurrency)
        self._req_count    = 0
        self._err_count    = 0
        self._lock         = asyncio.Lock()

        # WAF state
        self.waf_name:       Optional[str] = None
        self.waf_confidence: float          = 0.0

    async def __aenter__(self):
        limits = httpx.Limits(max_connections=self.concurrency, max_keepalive_connections=10)
        self._client = httpx.AsyncClient(
            verify=self.verify_ssl,
            proxy=self.proxy,
            timeout=float(self.timeout),
            limits=limits,
            follow_redirects=True
        )
        return self

    async def __aexit__(self, *_):
        if self._client:
            await self._client.aclose()

    def _redact(self, data: Any) -> Any:
        """Removes sensitive info from strings or dicts."""
        if isinstance(data, dict):
            return {k: ("[REDACTED]" if k.lower() in _SENSITIVE_HEADERS else self._redact(v)) for k, v in data.items()}
        if isinstance(data, str):
            res = data
            for p in _SENSITIVE_PATTERNS:
                res = p.sub("[REDACTED]", res)
            return res
        return data

    def _is_ssrf_risk(self, url: str) -> bool:
        """Checks if URL points to internal/private infrastructure."""
        if self.allow_internal:
            return False
        
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return True # Malformed
            
            # Resolve IP
            ip_addr = socket.gethostbyname(hostname)
            ip = ipaddress.ip_address(ip_addr)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
                logger.error(f"Target blocked by SSRF Shield: {ip} is internal/private (e.g. 10.0.0.0/8, 192.168.0.0/16).")
                return True
            return False
        except Exception:
            logger.error(f"SSRF Shield error resolving hostname for {url}. Blocking by default.")
            return True # If it can't be resolved or parsed safely, block it

    def _get_headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        h = {"User-Agent": random.choice(_USER_AGENTS), "Accept": "*/*"}
        h.update(self.base_headers)
        if extra: h.update(extra)
        return h

    async def request(
        self,
        method:  str,
        url:     str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params:  Optional[Dict]           = None,
        json:    Optional[Any]            = None,
        data:    Optional[Any]            = None,
    ) -> Response:
        """
        Safe async request with SSRF guard and rate limiting.
        """
        if self._is_ssrf_risk(url):
            logger.warning(f"SSRF Prevention: Blocked request to internal target -> {url}")
            return Response(url=url, method=method, error="SSRF_PROTECTION_TRIGGERED")

        # Global Rate Limit check
        async with self._lock:
            target_ip = urlparse(url).hostname or "unknown"
            now = time.perf_counter()
            start = self._rate_limit_start.get(target_ip, now)
            count = self._rate_limits.get(target_ip, 0)
            
            if now - start > 60:
                self._rate_limit_start[target_ip] = now
                self._rate_limits[target_ip] = 1
            else:
                if count >= self.rate_limit_per_minute:
                    logger.error(f"Rate Limit Shield: Dropping {method} {url} - Exceeded {self.rate_limit_per_minute} req/min.")
                    return Response(url=url, method=method, error="RATE_LIMIT_TRIGGERED")
                self._rate_limits[target_ip] = count + 1

        async with self._semaphore:
            if self.base_delay > 0:
                await asyncio.sleep(self.base_delay + (random.uniform(0, 0.1) if self.stealth else 0))

            full_headers = self._get_headers(headers)
            
            if self.dry_run:
                logger.info(f"DRY-RUN: {method} {url}")
                return Response(url=url, method=method, status=200, body="[DRY-RUN]")

            # Audit logging (Redacted)
            clean_url = self._redact(url)
            logger.debug(f"Request: {method} {clean_url}")

            if not self._client:
                # Fallback if not used as an async context manager
                async with httpx.AsyncClient(verify=self.verify_ssl, timeout=float(self.timeout)) as tmp_client:
                    return await self._execute(tmp_client, method, url, full_headers, params, json, data)
            
            return await self._execute(self._client, method, url, full_headers, params, json, data)

    async def _execute(self, client: httpx.AsyncClient, method: str, url: str, 
                        headers: dict, params: Optional[dict], json: Any, data: Any) -> Response:
        t0 = time.perf_counter()
        try:
            r = await client.request(
                method.upper(), url,
                headers=headers, params=params,
                json=json, data=data
            )
            elapsed = (time.perf_counter() - t0) * 1000
            
            resp = Response(
                url=url, method=method,
                status=r.status_code,
                headers=dict(r.headers),
                body=r.text,
                elapsed_ms=elapsed
            )
            
            async with self._lock:
                self._req_count += 1
            
            self._detect_waf_passive(resp)
            return resp

        except httpx.TimeoutException:
            async with self._lock: self._err_count += 1
            return Response(url=url, method=method, error="Timeout")
        except Exception as e:
            async with self._lock: self._err_count += 1
            return Response(url=url, method=method, error=str(e))

    # ── Convenience Wrappers ──────────────────────────────────────────────

    async def get(self, url: str, **kw) -> Response: return await self.request("GET", url, **kw)
    async def post(self, url: str, **kw) -> Response: return await self.request("POST", url, **kw)
    
    # ── WAF Detection (Passive) ───────────────────────────────────────────

    _WAF_HEADER_SIGS = {
        "Cloudflare": ["cf-ray", "cloudflare"],
        "AWS WAF":    ["x-amzn-requestid", "awselb"],
        "Akamai":     ["x-akamai-request-id", "akamai-ghost"],
    }

    def _detect_waf_passive(self, resp: Response) -> None:
        if not resp.ok: return
        h = str(resp.headers_lower).lower()
        for waf, sigs in self._WAF_HEADER_SIGS.items():
            if any(s in h for s in sigs):
                self.waf_name = waf
                self.waf_confidence = 80.0

    async def fingerprint(self, base_url: str) -> List[str]:
        resp = await self.get(base_url)
        if not resp.ok: return []
        techs = []
        h = resp.headers_lower
        if "nginx" in h.get("server", "").lower(): techs.append("Nginx")
        if "express" in h.get("x-powered-by", "").lower(): techs.append("Express.js")
        return list(set(techs))

    @property
    def request_count(self) -> int: return self._req_count
