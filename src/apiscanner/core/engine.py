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
from typing import Any, Dict, List, Optional, Tuple, Union, Callable, Coroutine
from urllib.parse import urlparse
import ipaddress

import httpx
from core.logger import logger
from core.metrics import RATE_LIMITED_REQS_TOTAL

# ─── Constants ───────────────────────────────────────────────────────────────

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
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
        concurrency:  int   = 50, # Optimizado: Limite Máx de 50 workers
        timeout:      int   = 2,  # Optimizado: 2s timeout por host
        max_retries:  int   = 3,  # Optimizado: 3 tentativas com backoff
        delay:        float = 0.2,
        stealth:      bool  = False,
        verify_ssl:   bool  = True,
        headers:      Optional[Dict[str, str]] = None,
        proxy:        Optional[str] = None,
        dry_run:      bool  = False,
        allow_internal: bool = False, # SSRF Protection Toggle
        on_security_event: Optional[Callable[[Dict[str, Any]], Coroutine[Any, Any, None]]] = None,
    ):
        self.concurrency   = min(concurrency, 50) # Boundary Estrito
        self.timeout       = timeout
        self.max_retries   = max_retries
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
        self.on_security_event = on_security_event
        
        self._rate_limits: Dict[str, int] = {}
        self._rate_limit_start: Dict[str, float] = {}

        self._client:      Optional[httpx.AsyncClient] = None
        self._semaphore    = asyncio.Semaphore(concurrency)
        self._req_count    = 0
        self._err_count    = 0
        self._lock         = asyncio.Lock()
        
        # Rate Limiting Dinâmico
        self._host_requests: Dict[str, List[float]] = {} # timestamps das últimas reqs por host
        self._global_requests: List[float] = [] # timestamps globais
        
        # WAF state & Evasion
        self.waf_name:       Optional[str] = None
        self.waf_confidence: float          = 0.0
        self.consecutive_errors: Dict[str, int] = {} # host -> errors (403/429)

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

    async def _is_ssrf_risk(self, url: str) -> bool:
        """Checks if URL points to internal/private infrastructure."""
        if self.allow_internal:
            return False
        
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return True # Malformed
            
            # Resolve IP
            ip_addr = await asyncio.get_event_loop().run_in_executor(None, socket.gethostbyname, hostname)
            ip = ipaddress.ip_address(ip_addr)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
                reason = f"{ip} is internal/private (SSRF Shield)"
                logger.error(f"Target blocked: {reason}")
                if self.on_security_event:
                    await self.on_security_event({
                        "url": url,
                        "reason": reason,
                        "category": "ssrf_blocked"
                    })
                return True
            return False
        except Exception as e:
            logger.error(f"SSRF Shield error resolving {url}: {e}")
            return True

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
        Executa uma requisição HTTP assíncrona segura encapsulada com:
        - Proteção contra SSRF e limites globais (Rate Limiting)
        - Pool de workers otimizado com controle via Semáforo 
        - Telemetria de log estruturada
        """
        if await self._is_ssrf_risk(url):
            logger.warning(f"SSRF Prevention: Blocked request to internal target -> {url}")
            return Response(url=url, method=method, error="SSRF_PROTECTION_TRIGGERED")

        # Global & Host Rate Limit check (Advanced)
        async with self._lock:
            target_host = urlparse(url).hostname or "unknown"
            now = time.time()
            
            # ── 1. Limite por Host (10 req/s) ──
            if target_host not in self._host_requests:
                self._host_requests[target_host] = []
            
            # Limpa timestamps antigos (> 1s)
            self._host_requests[target_host] = [t for t in self._host_requests[target_host] if now - t < 1.0]
            
            if len(self._host_requests[target_host]) >= 10:
                logger.warning(f"Internal Rate Limit (Host): Pausing 1s for {target_host}")
                RATE_LIMITED_REQS_TOTAL.labels(source="internal_host").inc()
                await asyncio.sleep(1.0)
                now = time.time() # Atualiza tempo após pausa
            
            self._host_requests[target_host].append(now)

            # ── 2. Limite Global (30 req/min) ──
            # Limpa timestamps antigos (> 60s)
            self._global_requests = [t for t in self._global_requests if now - t < 60.0]
            
            if len(self._global_requests) >= 30:
                logger.warning(f"Internal Rate Limit (Global): Exceeded 30 rpm. Pausing...")
                RATE_LIMITED_REQS_TOTAL.labels(source="internal_global").inc()
                await asyncio.sleep(2.0) # Pausa estratégica
                now = time.time()
            
            self._global_requests.append(now)

            # ── 3. Evasão de WAF (Consecutive 403/429) ──
            if self.consecutive_errors.get(target_host, 0) >= 3:
                reason = f"WAF/Rate Limit detected: Skipping {target_host} after 3 consecutive blocks"
                logger.error(reason)
                return Response(url=url, method=method, error="WAF_BLOCK_ESTABLISHED")

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

            task_id = id(asyncio.current_task())
            target_host = urlparse(url).hostname or "unknown"

            if self._client is None:
                # Fallback if not used as an async context manager
                async with httpx.AsyncClient(verify=self.verify_ssl, timeout=float(self.timeout)) as tmp_client:
                    return await self._execute_with_retry(tmp_client, method, url, full_headers, params, json, data, task_id, target_host)
            else:
                return await self._execute_with_retry(self._client, method, url, full_headers, params, json, data, task_id, target_host)

    async def _execute_with_retry(
        self, 
        client: httpx.AsyncClient, 
        method: str, 
        url: str, 
        headers: dict, 
        params: Optional[dict], 
        json: Any, 
        data: Any,
        task_id: int,
        target_host: str,
    ) -> Response:
        """
        Motor iterativo de requisições tolerante a falhas (Fault Tolerant).
        Implementa Retry Loop (padrão 3x) com Backoff Exponencial para estabilizar varreduras pesadas.
        """
        attempt: int = 0
        backoff: float = 1.0 # Multiplicador de Espera Exponencial
        last_error: str = "Unknown"
        resp: Optional[Response] = None

        while attempt < self.max_retries:
            attempt += 1
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
                
                # Controle de Erros Consecutivos (Evasion)
                if resp.status in (403, 429):
                    RATE_LIMITED_REQS_TOTAL.labels(source="external_waf").inc()
                    async with self._lock:
                        self.consecutive_errors[target_host] = self.consecutive_errors.get(target_host, 0) + 1
                elif resp.ok:
                    async with self._lock:
                        self.consecutive_errors[target_host] = 0 # Reset ao ter sucesso
                
                logger.info(f"[Task-{task_id}] [Host: {target_host}] {method} {url} - Status: {resp.status} - Time: {elapsed:.2f}ms (Attempt {attempt}/{self.max_retries})")
                
                # Falhas de servidor acionam os retries
                if resp.status in (429, 500, 502, 503, 504) and attempt < self.max_retries:
                    pass
                else:
                    return resp

            except httpx.TimeoutException:
                async with self._lock: self._err_count += 1
                last_error = "Timeout"
                elapsed = (time.perf_counter() - t0) * 1000
                logger.warning(f"[Task-{task_id}] [Host: {target_host}] {method} {url} - Status: Timeout - Time: {elapsed:.2f}ms (Attempt {attempt}/{self.max_retries})")
            except Exception as e:
                async with self._lock: self._err_count += 1
                last_error = str(e)
                elapsed = (time.perf_counter() - t0) * 1000
                logger.error(f"[Task-{task_id}] [Host: {target_host}] {method} {url} - Status: Error ({last_error}) - Time: {elapsed:.2f}ms (Attempt {attempt}/{self.max_retries})")
            
            # Backoff Delay antes da próxima tentativa
            if attempt < self.max_retries:
                logger.debug(f"[Task-{task_id}] Backoff acionado. Pausa de {backoff}s antes de reincidir.")
                await asyncio.sleep(backoff)
                backoff *= 2.0

        if resp is not None:
            return resp
        return Response(url=url, method=method, error=last_error)

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
