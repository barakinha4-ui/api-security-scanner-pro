import os
import json
import uuid
import socket
import logging
import asyncio
import ipaddress
import time
from urllib.parse import urlparse
from typing import List, Dict, Callable, Optional, Awaitable
from datetime import datetime

from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel, ValidationError, Field, UUID4
from jose import jwt, jwk, JWTError
from jose.utils import base64url_decode
import httpx
from cachetools import TTLCache
import redis.asyncio as redis

# Setup Redis Config
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
redis_client = redis.from_url(REDIS_URL, decode_responses=True)

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET", "supabase-secret")

# Cache for JWKS
jwks_cache = TTLCache(maxsize=1, ttl=3600)

async def get_jwks():
    if "jwks" in jwks_cache:
        return jwks_cache["jwks"]
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{SUPABASE_URL.rstrip('/')}/auth/v1/.well-known/jwks.json")
            resp.raise_for_status()
            jwks = resp.json()
            jwks_cache["jwks"] = jwks
            return jwks
    except Exception:
        return None

async def verify_supabase_jwt(token: str) -> Optional[dict]:
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid: return None

        result: Optional[dict] = await get_jwks()
        if not result or not isinstance(result, dict):
            return None
        
        keys: list = result.get("keys", [])
        key_data = next((k for k in keys if k.get("kid") == kid), None)
        if not key_data: return None

        public_key = jwk.construct(key_data)
        return jwt.decode(token, public_key.to_pem().decode('utf-8'), algorithms=["ES256"], audience="authenticated")
    except Exception:
        return None

# In-memory logging for stdout (Audit logs)
logger = logging.getLogger("audit_logger")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(message)s') # JSON pure
    ch.setFormatter(formatter)
    logger.addHandler(ch)

# ================= 1. Pydantic JWT Payload =================
class JWTPayload(BaseModel):
    """Pydantic model representing the expected JWT structure."""
    sub: UUID4
    exp: int
    roles: List[str] = Field(default_factory=list)

    def is_valid(self) -> bool:
        """Checks if the JWT is not expired."""
        return time.time() < self.exp

# ================= 2. IP and SSRF Filtering =================
INTERNAL_SUBNETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"), # Carrier-Grade NAT (RFC6598)
]
AWS_METADATA_IP = ipaddress.ip_address("169.254.169.254")

def is_internal_ip(ip_str: str) -> bool:
    """Blocks restricted internal/reserved networks."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip == AWS_METADATA_IP:
            return True
        for subnet in INTERNAL_SUBNETS:
            if ip in subnet:
                return True
        return False
    except ValueError:
        return True # Default deny if malformed

def resolve_and_check_ssrf(url: str) -> bool:
    """Resolves a hostname to an IP and blocks if it drops into internal space."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False

        # Permite apenas em ambiente de desenvolvimento (verifica env var)
        allow_private = os.getenv("ALLOW_PRIVATE_TARGETS", "false").lower() == "true"
        if hostname in ["vulnerable-api-lab", "app"] and allow_private:
            return False
            
        ip_addr = socket.gethostbyname(hostname)
        return is_internal_ip(ip_addr)
    except Exception:
        # Default deny on DNS resolution failures or malformed URLs
        return True

# ================= 3. Async Audit Logging =================
async def log_audit(user_id: str, ip: str, endpoint: str, status: int, correlation_id: uuid.UUID):
    """Writes an audit log entry in JSON format to stdout."""
    log_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "user_id": user_id,
        "ip": ip,
        "endpoint": endpoint,
        "status_code": status,
        "correlation_id": str(correlation_id)
    }
    logger.info(json.dumps(log_entry))

# ================= 4. FastAPI Middleware Core =================
class SecurityShieldMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[JSONResponse]]):
        correlation_id = uuid.uuid4()
        request.state.correlation_id = correlation_id
        
        user_id = "anonymous"
        client_ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown")
        
        # ────────── JWT/Auth Extraction ──────────
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            try:
                # 1. Tenta ES256 (JWKS)
                decoded = await verify_supabase_jwt(token)
                
                # 2. Fallback HS256
                if not decoded:
                    try:
                        decoded = jwt.decode(token, SUPABASE_JWT_SECRET, algorithms=["HS256"], audience="authenticated")
                    except Exception:
                        pass
                
                if decoded:
                    payload = JWTPayload(**decoded)
                    if not payload.is_valid():
                        return JSONResponse(status_code=401, content={"error": "JWT is expired"})
                    user_id = str(payload.sub)
            except (JWTError, ValidationError):
                pass
                
        # ────────── Sliding Window Rate Limit (Redis) ──────────
        limit_key = f"rl:{user_id}" if user_id != "anonymous" else f"rl:anon:{client_ip}"
        window_sec = 60
        max_limit = 100
        now = time.time()
        
        try:
            pipeline = redis_client.pipeline()
            # Remove keys older than the window
            pipeline.zremrangebyscore(limit_key, 0, now - window_sec)
            # Fetch count
            pipeline.zcard(limit_key)
            # Add current request
            pipeline.zadd(limit_key, {str(now): now})
            # Expire to save memory
            pipeline.expire(limit_key, window_sec)
            
            # Execute pipeline
            results = await pipeline.execute()
            req_count = results[1] # result of zcard
            
            if req_count >= max_limit:
                retry_after = window_sec
                return JSONResponse(
                    status_code=429,
                    content={"error": "rate_limit_exceeded", "retry_after": retry_after},
                    headers={"Retry-After": str(retry_after)}
                )
        except Exception as e:
            # Fallback: in-memory rate limit if Redis is down
            if not hasattr(self, '_mem_rate'):
                self._mem_rate: Dict[str, List[float]] = {}
            user_reqs = self._mem_rate.setdefault(client_ip, [])
            # Clean old entries
            user_reqs = [t for t in user_reqs if t > now - window_sec]
            self._mem_rate[client_ip] = user_reqs
            if len(user_reqs) >= 50:  # Lower limit when Redis is down
                return JSONResponse(
                    status_code=429,
                    content={"error": "rate_limit_exceeded", "retry_after": window_sec},
                    headers={"Retry-After": str(window_sec)}
                )
            user_reqs.append(now)

        # ────────── Proceed Request ──────────
        try:
            response = await call_next(request)
        except Exception as e:
            # Internal server error handler
            asyncio.create_task(log_audit(user_id, client_ip, f"{request.method} {request.url.path}", 500, correlation_id))
            raise e
            
        # ────────── Audit Logging (Async Task) ──────────
        asyncio.create_task(log_audit(user_id, client_ip, f"{request.method} {request.url.path}", response.status_code, correlation_id))

        # ────────── Security Headers Injection ──────────
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'self'"

        return response
