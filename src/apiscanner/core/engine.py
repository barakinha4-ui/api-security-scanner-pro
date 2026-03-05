"""
core/engine.py — Async HTTP Engine

Architecture:
  - asyncio event loop as primary scheduler
  - asyncio.Semaphore for concurrency control
  - asyncio.Queue for work distribution
  - asyncio.gather for parallel execution
  - requests in ThreadPoolExecutor for true I/O concurrency
    (drops in identically with httpx.AsyncClient when available)

This gives the full async/await API surface while working with stdlib only.
"""
from __future__ import annotations

import asyncio
import random
import re
import ssl
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter


# ─── User-Agent Pool ─────────────────────────────────────────────────────────

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "PostmanRuntime/7.36.1",
    "insomnia/9.0.0",
    "python-httpx/0.27.0",
    "curl/8.6.0",
]

_ACCEPT_VARIANTS = [
    "application/json",
    "application/json, text/plain, */*",
    "*/*",
    "application/json;charset=UTF-8",
]

_FAKE_IPS = [
    "10.0.0.1", "192.168.1.1", "172.16.0.1",
    "10.10.10.1", "192.168.0.100", "172.31.0.1",
]


# ─── Response Wrapper ─────────────────────────────────────────────────────────

@dataclass
class Response:
    """
    Unified response object — identical API whether backed by
    requests.Response, httpx.Response, or aiohttp.ClientResponse.
    """
    url:          str
    method:       str
    status:       int             = 0
    headers:      Dict[str, str]  = field(default_factory=dict)
    body:         str             = ""
    elapsed_ms:   float           = 0.0
    error:        Optional[str]   = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status > 0

    @property
    def headers_lower(self) -> Dict[str, str]:
        return {k.lower(): v for k, v in self.headers.items()}

    @property
    def content_type(self) -> str:
        return self.headers_lower.get("content-type", "")

    @property
    def is_json(self) -> bool:
        return "application/json" in self.content_type

    def json(self) -> Any:
        import json
        try:
            return json.loads(self.body)
        except Exception:
            return None

    def __bool__(self):
        return self.ok


# ─── Async HTTP Engine ────────────────────────────────────────────────────────

class AsyncEngine:
    """
    Fully async HTTP engine built on asyncio.

    Usage (async context):
        async with AsyncEngine(...) as eng:
            resp = await eng.get("https://target.com/api")
            results = await eng.gather([
                eng.get(url1),
                eng.post(url2, json=body),
            ])

    Usage (sync context, auto-creates event loop):
        eng = AsyncEngine(...)
        resp = eng.request_sync("GET", url)
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
        rate_limit:   int   = 0,   # max req/sec per host (0 = unlimited)
    ):
        self.concurrency  = concurrency
        self.timeout      = timeout
        self.base_delay   = delay
        self.stealth      = stealth
        self.verify_ssl   = verify_ssl
        self.base_headers = headers or {}
        self.proxy        = proxy
        self.rate_limit   = rate_limit

        # Semaphore is created per-loop inside async context
        self._semaphore:  Optional[asyncio.Semaphore] = None
        self._executor    = ThreadPoolExecutor(max_workers=concurrency)
        self._lock        = asyncio.Lock() if False else threading.Lock()  # sync lock for counters
        self._req_count   = 0
        self._err_count   = 0

        # Per-host rate limiting state
        self._host_times: Dict[str, List[float]] = {}

        # WAF detection state
        self.waf_name:       Optional[str] = None
        self.waf_confidence: float          = 0.0

    async def __aenter__(self):
        self._semaphore = asyncio.Semaphore(self.concurrency)
        return self

    async def __aexit__(self, *_):
        self._executor.shutdown(wait=False)

    # ── Header building ────────────────────────────────────────────────────

    def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        h: Dict[str, str] = {}

        if self.stealth:
            h["User-Agent"]      = random.choice(_USER_AGENTS)
            h["Accept"]          = random.choice(_ACCEPT_VARIANTS)
            fake_ip              = random.choice(_FAKE_IPS)
            h["X-Forwarded-For"] = fake_ip
            h["X-Real-IP"]       = fake_ip
            h["X-Request-ID"]    = f"{random.randint(10**9, 10**10-1)}"
        else:
            h["User-Agent"] = "APISecurityScanner/2.0 (Authorized Security Testing)"
            h["Accept"]     = "application/json, */*"

        h["Accept-Language"] = "en-US,en;q=0.9"
        h["Accept-Encoding"] = "gzip, deflate"
        h["Connection"]      = "keep-alive"

        h.update(self.base_headers)
        if extra:
            h.update(extra)
        return h

    # ── Delay logic ───────────────────────────────────────────────────────

    async def _delay(self, host: str) -> None:
        if self.stealth:
            jitter = random.uniform(0, self.base_delay * 1.5)
            await asyncio.sleep(self.base_delay + jitter)
        elif self.base_delay > 0:
            await asyncio.sleep(self.base_delay)

    # ── Core async request ────────────────────────────────────────────────

    async def request(
        self,
        method:  str,
        url:     str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params:  Optional[Dict]           = None,
        json:    Optional[Any]            = None,
        data:    Optional[Any]            = None,
        allow_redirects: bool             = True,
    ) -> Response:
        """
        Async HTTP request. Returns Response — never raises.

        Internally runs the blocking requests call in a ThreadPoolExecutor
        so it doesn't block the event loop. When httpx or aiohttp is
        available, swap _do_request for a native async implementation.
        """
        sem = self._semaphore or asyncio.Semaphore(self.concurrency)

        async with sem:
            parsed = urlparse(url)
            await self._delay(parsed.netloc)

            loop = asyncio.get_event_loop()
            resp = await loop.run_in_executor(
                self._executor,
                lambda: self._do_request(method, url,
                                         headers=headers, params=params,
                                         json=json, data=data,
                                         allow_redirects=allow_redirects),
            )

            with self._lock:
                if resp.ok:
                    self._req_count += 1
                else:
                    self._err_count += 1

            self._detect_waf_passive(resp)
            return resp

    def _do_request(
        self, method: str, url: str,
        headers=None, params=None,
        json=None, data=None, allow_redirects=True,
    ) -> Response:
        """Blocking requests call — runs in thread pool."""
        session = requests.Session()
        adapter = HTTPAdapter(max_retries=1)
        session.mount("http://",  adapter)
        session.mount("https://", adapter)

        final_headers = self._headers(headers)
        proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else {}

        t0 = time.perf_counter()
        try:
            r = session.request(
                method.upper(), url,
                headers=final_headers,
                params=params,
                json=json,
                data=data,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=allow_redirects,
                proxies=proxies,
            )
            elapsed = (time.perf_counter() - t0) * 1000
            return Response(
                url=url, method=method,
                status=r.status_code,
                headers=dict(r.headers),
                body=self._safe_text(r),
                elapsed_ms=elapsed,
            )
        except requests.exceptions.SSLError as e:
            return Response(url=url, method=method, error=f"SSL: {e}")
        except requests.exceptions.ConnectionError as e:
            return Response(url=url, method=method, error=f"Connection: {e}")
        except requests.exceptions.Timeout:
            elapsed = (time.perf_counter() - t0) * 1000
            return Response(url=url, method=method, elapsed_ms=elapsed, error="Timeout")
        except Exception as e:
            return Response(url=url, method=method, error=str(e))
        finally:
            session.close()

    @staticmethod
    def _safe_text(r: requests.Response) -> str:
        try:
            return r.text
        except Exception:
            return r.content.decode("utf-8", errors="replace")

    # ── Convenience wrappers ──────────────────────────────────────────────

    async def get(self, url: str, **kw) -> Response:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw) -> Response:
        return await self.request("POST", url, **kw)

    async def options(self, url: str, **kw) -> Response:
        return await self.request("OPTIONS", url, **kw)

    async def head(self, url: str, **kw) -> Response:
        return await self.request("HEAD", url, **kw)

    # ── Batch execution ───────────────────────────────────────────────────

    async def gather(self, coroutines: List) -> List[Response]:
        """Run multiple request coroutines concurrently via asyncio.gather."""
        return list(await asyncio.gather(*coroutines, return_exceptions=False))

    async def map_requests(
        self,
        method: str,
        urls:   List[str],
        **shared_kwargs,
    ) -> List[Response]:
        """Send the same request to many URLs concurrently."""
        coros = [self.request(method, url, **shared_kwargs) for url in urls]
        return await self.gather(coros)

    async def batch_post(
        self,
        url:     str,
        bodies:  List[Any],
        **shared_kwargs,
    ) -> List[Response]:
        """POST multiple bodies to the same URL concurrently."""
        coros = [self.post(url, json=body, **shared_kwargs) for body in bodies]
        return await self.gather(coros)

    # ── Sync bridge ───────────────────────────────────────────────────────

    def run(self, coro) -> Any:
        """Run a coroutine from sync context."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                fut = asyncio.run_coroutine_threadsafe(coro, loop)
                return fut.result(timeout=self.timeout * 2)
        except RuntimeError:
            pass
        return asyncio.run(coro)

    def request_sync(self, method: str, url: str, **kw) -> Response:
        """Sync convenience wrapper around async request."""
        return self.run(self.request(method, url, **kw))

    # ── WAF Detection ─────────────────────────────────────────────────────

    _WAF_HEADER_SIGS: Dict[str, List[str]] = {
        "Cloudflare":  ["cf-ray", "__cfduid", "cloudflare"],
        "AWS WAF":     ["x-amzn-requestid", "x-amz-cf-id", "awselb"],
        "Akamai":      ["x-akamai-request-id", "akamai-ghost"],
        "Imperva":     ["visid_incap", "incap_ses", "x-cdn=Incapsula"],
        "Sucuri":      ["x-sucuri-id"],
        "F5 BIG-IP":   ["bigipserver", "ts000"],
        "ModSecurity": ["mod_security", "noyb"],
        "Fastly":      ["x-fastly-request-id"],
        "Barracuda":   ["barra_counter_session"],
    }

    _WAF_BODY_SIGS: Dict[str, List[str]] = {
        "Cloudflare":  ["cloudflare", "cf-ray", "attention required"],
        "AWS WAF":     ["request blocked by aws", "403 forbidden"],
        "Akamai":      ["access denied", "akamai reference"],
        "Imperva":     ["incapsula incident"],
        "Sucuri":      ["sucuri website firewall"],
        "F5 BIG-IP":   ["the requested url was rejected"],
        "ModSecurity": ["406 not acceptable", "mod_security"],
    }

    def _detect_waf_passive(self, resp: Response) -> None:
        if not resp.ok:
            return
        combined = (str(resp.headers_lower) + resp.headers_lower.get("set-cookie", "")).lower()
        for waf, sigs in self._WAF_HEADER_SIGS.items():
            hits = sum(1 for s in sigs if s in combined)
            if hits:
                conf = min(hits / len(sigs) * 100, 100.0)
                with self._lock:
                    if conf > self.waf_confidence:
                        self.waf_confidence = conf
                        self.waf_name = waf

    async def detect_waf(self, base_url: str) -> Tuple[Optional[str], float]:
        """
        Active WAF probe — sends a deliberately malicious payload and
        analyses the response to identify WAF vendor.
        """
        probe = f"{base_url.rstrip('/')}/?__test=1'\"<script>alert(1)</script>"
        resp = await self.get(probe)

        if resp.ok:
            body = resp.body.lower()
            for waf, sigs in self._WAF_BODY_SIGS.items():
                hits = sum(1 for s in sigs if s in body)
                if hits:
                    conf = min(hits / len(sigs) * 100 + 35, 100.0)
                    with self._lock:
                        if conf > self.waf_confidence:
                            self.waf_confidence = conf
                            self.waf_name = waf

            # Generic: 403/406 with very short body
            if resp.status in (403, 406, 429, 503) and len(resp.body) < 3000:
                if not self.waf_name:
                    self.waf_name       = "Generic WAF/Rate Limit"
                    self.waf_confidence = 50.0

        return self.waf_name, self.waf_confidence

    # ── Technology Fingerprinting ─────────────────────────────────────────

    async def fingerprint(self, base_url: str) -> List[str]:
        resp = await self.get(base_url)
        if not resp.ok:
            return []

        techs: List[str] = []
        h = resp.headers_lower
        body = resp.body.lower()

        checks: Dict[str, Any] = {
            "Nginx":         lambda: "nginx"        in h.get("server", ""),
            "Apache":        lambda: "apache"       in h.get("server", ""),
            "IIS":           lambda: "iis"          in h.get("server", ""),
            "Express.js":    lambda: "express"      in h.get("x-powered-by", ""),
            "PHP":           lambda: "php"          in h.get("x-powered-by", ""),
            "ASP.NET":       lambda: "asp.net"      in h.get("x-powered-by", "") or "aspnetcore" in h.get("server", ""),
            "Django":        lambda: "csrftoken"    in h.get("set-cookie", ""),
            "Rails":         lambda: "x-request-id" in h and "ruby" in h.get("x-runtime", ""),
            "Spring Boot":   lambda: "x-application-context" in h,
            "Cloudflare":    lambda: "cf-ray"       in h,
            "CloudFront":    lambda: "x-amz-cf-id"  in h,
            "GraphQL API":   lambda: '"data"'       in resp.body and '"errors"' in resp.body,
        }
        for tech, fn in checks.items():
            try:
                if fn():
                    techs.append(tech)
            except Exception:
                pass
        return list(set(techs))

    # ── Stats ─────────────────────────────────────────────────────────────

    @property
    def request_count(self) -> int:
        return self._req_count

    @property
    def error_count(self) -> int:
        return self._err_count
