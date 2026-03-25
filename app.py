# app.py - SaaS Wrapper com Scanner Real Integrado + Redis
# Versão corrigida para estabilidade de WebSocket (Heartbeat + Pub/Sub)

import os
import sys
import json
import uuid
import logging
import asyncio
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Union
from urllib.parse import urlparse

# Adiciona src/ ao path — permite imports como:
# - from apiscanner.core.x import ...
# - from apiscanner.scanner import ...
# NOTA: Não adicionar src/apiscanner/ também, pois causaria
# duplo registro das métricas Prometheus (identidades distintas).
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_PATH = os.path.join(BASE_DIR, "src")
if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)

from pydantic import BaseModel, ValidationError, field_validator
import jwt
from jwt.exceptions import InvalidTokenError
from jose import jwt as jose_jwt
from jose import jwk
import httpx
from cachetools import TTLCache
from dotenv import load_dotenv
import uvicorn

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, Request, Header, Response, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from redis.exceptions import RedisError
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
import time

# Metrics e Core modules
try:
    from apiscanner.core.metrics import (
        SCANNER_JOBS_TOTAL, SCANNER_ACTIVE_JOBS, SCANNER_FINDINGS_TOTAL,
        HTTP_REQUEST_DURATION
    )
    from apiscanner.core.database import AsyncSessionLocal, get_db, init_models
    from apiscanner.core.models_db import ScanDB, FindingDB, Organization, OrganizationMember, Subscription, PlanUsage
    from apiscanner.core.billing_logic import check_scan_quota, increment_usage, create_checkout_session, handle_stripe_webhook
    from apiscanner.scanner import Scanner
    from sqlalchemy import select, update
    SCANNER_AVAILABLE = True
except ImportError as e:
    SCANNER_AVAILABLE = False
    print(f"[WARN]  Warning: apiscanner modules not found: {e}")

# Redis e Repository
from redis_config import get_redis, ping_redis
from repository.job_repository import JobRepository
from security_shield import SecurityShieldMiddleware, resolve_and_check_ssrf

# Celery
from celery_app import app as celery_app

# Supabase Client
from supabase import create_client, Client

# Carrega ambiente
load_dotenv()

API_KEY_SECRET      = os.getenv("API_KEY_SECRET")
if not API_KEY_SECRET:
    if os.getenv("ENVIRONMENT", "development") == "production":
        raise RuntimeError("API_KEY_SECRET must be set in production environment!")
    else:
        print("[WARN] API_KEY_SECRET not set. Using generated development key.")
        API_KEY_SECRET = secrets.token_hex(32)
        
SUPABASE_URL        = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY        = os.getenv("SUPABASE_KEY", "")
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET")
if not SUPABASE_JWT_SECRET:
    if os.getenv("ENVIRONMENT", "development") == "production":
        raise RuntimeError("SUPABASE_JWT_SECRET must be set in production environment!")
    else:
        print("[WARN] SUPABASE_JWT_SECRET not set. Using generated development key.")
        SUPABASE_JWT_SECRET = secrets.token_hex(32)
STRIPE_SECRET_KEY   = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
STRIPE_PRICE_ID     = os.getenv("STRIPE_PRICE_ID")
STRIPE_SUCCESS_URL  = os.getenv("STRIPE_SUCCESS_URL", "http://localhost:3000/billing/success")
STRIPE_CANCEL_URL   = os.getenv("STRIPE_CANCEL_URL", "http://localhost:3000/billing/cancel")


# Inicializa Cliente Supabase
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

try:
    import base64
    # Tenta decodificar como Base64 apenas se for uma string válida
    _decoded = base64.b64decode(SUPABASE_JWT_SECRET + '==')
    # Valida que o resultado faz sentido (≥ 32 bytes)
    if len(_decoded) >= 32:
        SUPABASE_JWT_SECRET_BIN = _decoded
    else:
        SUPABASE_JWT_SECRET_BIN = SUPABASE_JWT_SECRET.encode()
except Exception:
    # Secret é texto puro — usa direto como bytes
    SUPABASE_JWT_SECRET_BIN = SUPABASE_JWT_SECRET.encode() if isinstance(SUPABASE_JWT_SECRET, str) else SUPABASE_JWT_SECRET

SCAN_TIMEOUT    = int(os.getenv("SCAN_TIMEOUT", "300"))
MAX_CONCURRENCY = int(os.getenv("MAX_CONCURRENCY", "20"))

# Lifecycle do app
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan_app(app: FastAPI):
    # Inicializa banco de dados se o scanner estiver disponível
    if SCANNER_AVAILABLE:
        try:
            await init_models()
            print("[OK] DB models initialized")
            
            # Migração Legada: Atribuir scans sem org a uma org padrão
            async with AsyncSessionLocal() as db:
                # 1. Busca scans sem org
                result = await db.execute(select(ScanDB).where(ScanDB.organization_id == None))
                legacy_scans = result.scalars().all()
                if legacy_scans:
                    print(f"[MIGRATE] Migrating {len(legacy_scans)} legacy scans...")
                    # Cria Org de Migração se necessário
                    org_id = "default-org-legacy"
                    org_check = await db.get(Organization, org_id)
                    if not org_check:
                        new_org = Organization(id=org_id, name="Legacy Migration Org", owner_id="system")
                        db.add(new_org)
                        await db.commit()
                    
                    # Atualiza em massa
                    await db.execute(update(ScanDB).where(ScanDB.organization_id == None).values(organization_id=org_id))
                    await db.commit()
                    print("[OK] Legacy migration complete")
        except Exception as e:
            print(f"[WARN]  DB init or migration error (non-fatal): {e}")
    else:
        print("[WARN]  Scanner unavailable — skipping DB init")

    # Inicia cleanup loop em background
    cleanup_task = asyncio.create_task(_cleanup_loop())
    print("[OK] Background cleanup loop started")

    yield

    # Cleanup ao shutdown
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass
    print("[STOP] Cleanup loop stopped")

# Configuração FastAPI
app = FastAPI(
    title="API Security Scanner Pro",
    description="""## Enterprise API Vulnerability Scanner
    
### Funcionalidades
- **Scanner de Vulnerabilidades**: Detecte SQLi, XSS, BOLA, IDOR, SSRF e mais
- **Autenticação Automática**: Suporte a JWT, OAuth, API Keys, Basic Auth
- **Relatórios Profissionais**: Export em JSON, HTML, Markdown, SARIF
- **Integração CI/CD**: GitHub Actions, GitLab CI, Jenkins
- **GraphQL Support**: Detecção específica de vulnerabilidades GraphQL

### Planos
- **Gratuito**: 5 scans/mês, até 50 endpoints
- **Pro**: Scans ilimitados, API access, suporte prioritário
- **Enterprise**: Instalações on-premise, SLA garantido

### Autenticação
Use o header `Authorization: Bearer <token>` com seu token de API.""",
    version="2.1.0",
    lifespan=lifespan_app,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    contact={
        "name": "API Security Scanner Pro",
        "url": "https://api-security-scanner.pro",
        "email": "contato@api-security-scanner.pro"
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT"
    },
)

_allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
if "*" in _allowed_origins and os.getenv("ENVIRONMENT") == "production":
    raise RuntimeError("Cannot use '*' origin with credentials in production!")
    
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)
app.add_middleware(SecurityShieldMiddleware)

from fastapi.responses import FileResponse
DASHBOARD_PATH = r'C:\Users\gusta\Desktop\api-security\api-security-scanner-pro\dashboard.html'
@app.get('/dashboard')
async def dashboard():
    return FileResponse(DASHBOARD_PATH)

security = HTTPBearer()
job_repo = JobRepository()

# Logging Estruturado JSON
class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level":    record.levelname,
            "message":  record.getMessage(),
            "module":   record.module,
            "job_id":   getattr(record, "job_id", None),
        }
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_obj)

logger = logging.getLogger("app_logger")
logger.setLevel(logging.INFO)
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(JSONFormatter())
    logger.addHandler(_handler)

# Middlewares
@app.middleware("http")
async def prometheus_latency_middleware(request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time
    if request.url.path != "/metrics":
        HTTP_REQUEST_DURATION.labels(method=request.method, endpoint=request.url.path).observe(duration)
    return response

# Models
class ScanRequest(BaseModel):
    target:      str
    ports:       List[int]       = [22, 80, 443]
    timeout:     Optional[int]   = None
    concurrency: Optional[int]   = None
    scan_type:   Optional[str]   = "full"
    plugins:     Optional[List[str]] = None
    headers:     Optional[Dict[str, str]] = None
    
    @field_validator('target')
    @classmethod
    def validate_target(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError('Target must start with http:// or https://')
        return v
    
    @field_validator('ports')
    @classmethod
    def validate_ports(cls, v):
        if not v:
            raise ValueError('Ports cannot be empty')
        if any(p < 1 or p > 65535 for p in v):
            raise ValueError('Ports must be between 1 and 65535')
        if len(v) > 100:
            raise ValueError('Maximum 100 ports allowed')
        return v
    
    @field_validator('timeout')
    @classmethod
    def validate_timeout(cls, v):
        if v is not None and (v < 1 or v > 3600):
            raise ValueError('Timeout must be between 1 and 3600 seconds')
        return v
    
    @field_validator('concurrency')
    @classmethod
    def validate_concurrency(cls, v):
        if v is not None and (v < 1 or v > 100):
            raise ValueError('Concurrency must be between 1 and 100')
        return v

class JWTPayload(BaseModel):
    sub:  str
    exp:  int
    role: Optional[str] = "authenticated"

class AuthContext(BaseModel):
    user_id:        str
    organization_id: str
    role:           str

class AuthRequest(BaseModel):
    email:    str
    password: str

# Auth Service
class JWKSService:
    def __init__(self, supabase_url: str):
        self.jwks_url = f"{supabase_url.rstrip('/')}/auth/v1/.well-known/jwks.json"
        self.cache = TTLCache(maxsize=1, ttl=3600)
        self.client = httpx.AsyncClient()

    async def get_jwks(self):
        if "jwks" in self.cache: return self.cache["jwks"]
        try:
            resp = await self.client.get(self.jwks_url)
            resp.raise_for_status()
            jwks = resp.json()
            self.cache["jwks"] = jwks
            return jwks
        except Exception: return None

    async def verify_token(self, token: str) -> Optional[dict]:
        try:
            header = jose_jwt.get_unverified_header(token)
            kid = header.get("kid")
            jwks = await self.get_jwks()
            if not jwks or not isinstance(jwks, dict): return None
            
            keys = jwks.get("keys", [])
            key_data = next((k for k in keys if k.get("kid") == kid), None)
            if not key_data: return None
            public_key = jwk.construct(key_data)
            return jose_jwt.decode(token, public_key.to_pem().decode('utf-8'), algorithms=["ES256"], audience="authenticated")
        except Exception: return None

auth_service = JWKSService(SUPABASE_URL or "")

async def verify_access(credentials: HTTPAuthorizationCredentials = Security(security)) -> str:
    token = credentials.credentials
    if secrets.compare_digest(str(token), str(API_KEY_SECRET)): return "api_key_user"
    
    payload_dict = await auth_service.verify_token(token)
    if payload_dict: return payload_dict["sub"]

    try:
        pd = jwt.decode(token, SUPABASE_JWT_SECRET_BIN, algorithms=["HS256"], audience="authenticated")
        return pd["sub"]
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

# Cache leve de Org (1 min) para não bater no DB em cada request
org_cache = TTLCache(maxsize=1000, ttl=60)

async def get_auth_context(
    user_id: str = Depends(verify_access),
    db: AsyncSessionLocal = Depends(get_db)
) -> AuthContext:
    if user_id == "api_key_user":
        return AuthContext(user_id=user_id, organization_id="default-org-legacy", role="admin")

    # 1. Verifica Cache
    if user_id in org_cache:
        return org_cache[user_id]

    # 2. Busca Organização
    # Tenta encontrar a primeira organização onde o usuário é membro
    result = await db.execute(
        select(OrganizationMember.organization_id, OrganizationMember.role)
        .where(OrganizationMember.user_id == user_id)
        .limit(1)
    )
    membership = result.first()

    if not membership:
        # AUTO-PROVISIONING (Regra: Se não tem org, cria uma Personal Workspace)
        try:
            org_id = f"org_{uuid.uuid4().hex[:8]}"
            new_org = Organization(id=org_id, name="Personal Workspace", owner_id=user_id)
            new_member = OrganizationMember(organization_id=org_id, user_id=user_id, role="admin")
            db.add(new_org)
            db.add(new_member)
            await db.commit()
            ctx = AuthContext(user_id=user_id, organization_id=org_id, role="admin")
            org_cache[user_id] = ctx
            return ctx
        except Exception as e:
            logger.error(f"Auto-provisioning failed for {user_id}: {e}")
            raise HTTPException(status_code=500, detail="Failed to initialize workspace")

    ctx = AuthContext(user_id=user_id, organization_id=membership.organization_id, role=membership.role)
    org_cache[user_id] = ctx
    return ctx

# Pub/Sub Helpers
def _ws_channel(job_id: str) -> str:
    return f"ws:job:{job_id}"

async def _publish(job_id: str, payload: dict) -> None:
    try:
        r = get_redis()
        await r.publish(_ws_channel(job_id), json.dumps(payload))
    except Exception as e:
        logger.warning(f"PubSub error: {e}")

# Endpoints REST
@app.get("/health")
async def health():
    ok, ms = await ping_redis()
    return {"status": "ok" if ok else "unhealthy", "redis": ok, "latency": ms}

@app.get("/api/status/redis")
async def redis_status():
    try:
        r = get_redis()
        await r.ping()
        logger.info("Redis ping OK")
        return {"status": "online"}
    except Exception as e:
        logger.error(f"Redis ping failed: {e}")
        return {"status": "offline", "error": str(e)}

@app.get("/api/debug/routes")
async def debug_routes():
    return [{"path": route.path, "name": route.name, "methods": list(route.methods)} for route in app.routes]

# ═══════════════════════════════════════════════════════════════
# AUTH ENDPOINTS (SUPABASE)
# ═══════════════════════════════════════════════════════════════

@app.post("/api/auth/register")
async def register(req: AuthRequest):
    try:
        res = supabase.auth.sign_up({
            "email": req.email,
            "password": req.password,
        })
        return {"message": "User created", "user": res.user}
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/auth/login")
async def login(req: AuthRequest):
    try:
        res = supabase.auth.sign_in_with_password({
            "email": req.email,
            "password": req.password,
        })
        return {
            "access_token": res.session.access_token,
            "token_type": "bearer",
            "user": {
                "id": res.user.id,
                "email": res.user.email
            }
        }
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=401, detail="Invalid credentials or user not found")

@app.get("/health")
async def health_check():
    """Rota de diagnóstico para o Healthcheck do Railway"""
    return {"status": "healthy", "service": "api-scanner-pro"}

@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.post("/api/scan", status_code=202)
async def create_scan(req: ScanRequest, ctx: AuthContext = Depends(get_auth_context), db: AsyncSession = Depends(get_db)):
    if resolve_and_check_ssrf(req.target):
        return JSONResponse(status_code=403, content={"error": "SSRF blocked"})
    
    # --- Validação de Quota SaaS ---
    await check_scan_quota(ctx.organization_id, db)

    job_id = str(uuid.uuid4())
    job_data = {
        "id": job_id, "target": req.target, "status": "queued", 
        "user_id": ctx.user_id, 
        "organization_id": ctx.organization_id, 
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await job_repo.create(job_id, job_data, organization_id=ctx.organization_id)
    
    # Incrementa uso
    await increment_usage(ctx.organization_id, db)

    # Envia a tarefa para a fila do Celery Worker
    from tasks.scan_tasks import run_api_scan
    run_api_scan.delay(
        target=req.target, 
        user_id=ctx.user_id, 
        job_id=job_id, 
        scan_type=req.scan_type, 
        ports=req.ports, 
        organization_id=ctx.organization_id, 
        headers=req.headers
    )
    return {"job_id": job_id, "status": "enqueued", "organization_id": ctx.organization_id}


async def _run_scan_inline(target: str, user_id: str, job_id: str, scan_type: str, ports, organization_id: str, headers: dict = None):
    """Executa scan diretamente (sem Celery Worker)"""
    job_repo = JobRepository()
    
    async def _publish(job_id: str, payload: dict):
        try:
            r = get_redis()
            await r.publish(f"ws:job:{job_id}", json.dumps(payload, ensure_ascii=False))
        except:
            pass

    try:
        await job_repo.update(job_id, {"status": "running", "started_at": datetime.now(timezone.utc).isoformat()}, organization_id=organization_id)
        await _publish(job_id, {"type": "log", "status": "running", "message": f"Scan started: {target}", "job_id": job_id})

        src_path = os.path.join(os.path.dirname(__file__), "src")
        if src_path not in sys.path:
            sys.path.insert(0, src_path)

        from apiscanner.core.engine import AsyncEngine
        from apiscanner.scanner import Scanner

        async def on_finding(f):
            fd = f.to_dict() if hasattr(f, "to_dict") else {}
            await job_repo.append_finding(job_id, fd, organization_id=organization_id)
            await _publish(job_id, {"type": "finding", "job_id": job_id, "data": fd})

        async def on_log(msg):
            await _publish(job_id, {"type": "log", "message": str(msg), "timestamp": datetime.now(timezone.utc).isoformat()})

        async with AsyncEngine(concurrency=20, timeout=300, headers=headers) as engine:
            scanner = Scanner(target=target, engine=engine, scan_type=scan_type, on_finding=on_finding, on_log=on_log)
            result = await scanner.run()

        summary = result.summary if hasattr(result, 'summary') else {}
        findings = len(result.findings) if hasattr(result, 'findings') else 0

        # Conta por severidade
        critical = sum(1 for f in result.findings if getattr(f, 'severity', '') == 'critical')
        high = sum(1 for f in result.findings if getattr(f, 'severity', '') == 'high')
        medium = sum(1 for f in result.findings if getattr(f, 'severity', '') == 'medium')
        low = sum(1 for f in result.findings if getattr(f, 'severity', '') == 'low')

        await job_repo.update(job_id, {"status": "completed", "completed_at": datetime.now(timezone.utc).isoformat(), "summary": summary}, organization_id=organization_id)
        await _publish(job_id, {"status": "completed", "type": "status", "job_id": job_id, "summary": summary, "message": f"Scan completed - {findings} findings"})

        # Envia notificação Slack/Teams
        try:
            from src.apiscanner.notifications import notifications
            report_url = f"{os.getenv('APP_URL', 'http://localhost:8000')}/api/reports/{job_id}"
            await notifications.notify_scan_completed(
                target=target,
                status="completed",
                findings_count=findings,
                critical=critical,
                high=high,
                medium=medium,
                low=low,
                report_url=report_url
            )
        except Exception as notif_err:
            print(f"Notification error: {notif_err}")

    except Exception as e:
        import traceback
        await job_repo.update(job_id, {"status": "failed", "error": str(e)}, organization_id=organization_id)
        await _publish(job_id, {"status": "failed", "type": "status", "job_id": job_id, "error": str(e), "message": f"Scan failed: {e}"})
        
        # Envia notificação de falha
        try:
            from src.apiscanner.notifications import notifications
            await notifications.notify_scan_completed(
                target=target,
                status="failed",
                findings_count=0,
                critical=0,
                high=0,
                medium=0,
                low=0
            )
        except Exception:
            pass

@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str, ctx: AuthContext = Depends(get_auth_context)):
    job = await job_repo.get(job_id, organization_id=ctx.organization_id)
    if not job: raise HTTPException(status_code=404)
    # Validação redundante de segurança: Garante que a Org do job bate com a do usuário
    if job.get("organization_id") != ctx.organization_id and ctx.user_id != "api_key_user":
        raise HTTPException(status_code=403, detail="DataAccessDenied: Job belongs to another tenant")
    return job


# ═══════════════════════════════════════════════════════════════
# DOWNLOAD DE RELATÓRIOS
# ═══════════════════════════════════════════════════════════════

REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")

@app.get("/api/reports")
async def list_reports(ctx: AuthContext = Depends(get_auth_context)):
    """Lista todos os relatórios disponíveis para download."""
    import glob
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    # Lista relatórios (html e pdf)
    patterns = ["*.html", "*.pdf", "*.json"]
    reports = []
    
    for pattern in patterns:
        for f in glob.glob(os.path.join(REPORTS_DIR, pattern)):
            stat = os.stat(f)
            reports.append({
                "filename": os.path.basename(f),
                "size": stat.st_size,
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat()
            })
    
    # Ordena por data
    reports.sort(key=lambda x: x["created"], reverse=True)
    return {"reports": reports[:50]}


@app.get("/api/reports/{filename}")
async def download_report(filename: str, ctx: AuthContext = Depends(get_auth_context)):
    """Baixa um relatório específico em HTML, PDF ou JSON."""
    import glob
    
    # Validação de segurança: impede path traversal
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    # Busca o arquivo
    os.makedirs(REPORTS_DIR, exist_ok=True)
    search_patterns = [f"*{filename}*.*", f"report_{filename}.*"]
    
    found_file = None
    for pattern in search_patterns:
        matches = glob.glob(os.path.join(REPORTS_DIR, pattern))
        if matches:
            found_file = matches[0]
            break
    
    if not found_file or not os.path.exists(found_file):
        raise HTTPException(status_code=404, detail="Report not found")
    
    from fastapi.responses import FileResponse
    import mimetypes
    
    media_type = mimetypes.guess_type(found_file)[0] or "application/octet-stream"
    
    return FileResponse(
        found_file, 
        media_type=media_type,
        filename=os.path.basename(found_file)
    )

# ═══════════════════════════════════════════════════════════════
# WEBSOCKET HANDLER — reescrito com polling e logging explícito
# ═══════════════════════════════════════════════════════════════
# Track WebSocket connections per IP to prevent DoS
_ws_connections: Dict[str, int] = {}
_WS_MAX_PER_IP = 5

@app.websocket("/ws/logs/{job_id}")
async def websocket_logs(websocket: WebSocket, job_id: str) -> None:
    client_ip = websocket.client.host if websocket.client else "unknown"
    logger.info(f"WS incoming: job={job_id} client={client_ip}")
    
    # Rate limit WS connections per IP
    if _ws_connections.get(client_ip, 0) >= _WS_MAX_PER_IP:
        await websocket.close(code=1013, reason="Too many connections")
        return
    _ws_connections[client_ip] = _ws_connections.get(client_ip, 0) + 1
    
    pubsub = None

    try:
        # ── 1. Aceita handshake imediatamente ───────────────────
        await websocket.accept()
        logger.info(f"WS accepted: job={job_id}")

        # ── 2. Autenticação (aguarda JSON com token) ─────────────
        try:
            auth_payload = await asyncio.wait_for(websocket.receive_json(), timeout=5.0)
        except asyncio.TimeoutError:
            logger.warning(f"WS auth timeout: job={job_id}")
            await websocket.close(code=1008, reason="Auth timeout")
            return
        except json.JSONDecodeError:
            logger.warning(f"WS auth bad JSON: job={job_id}")
            await websocket.close(code=1008, reason="Invalid auth format")
            return

        token = auth_payload.get("token", "")
        user_id_ws: Optional[str] = None
        org_id_ws:  Optional[str] = None

        if secrets.compare_digest(str(token), str(API_KEY_SECRET)):
            user_id_ws = "api_key_user"
            org_id_ws  = "default-org-legacy"
        else:
            try:
                # Resolve contexto via token (simulando get_auth_context manual p/ WS)
                # NOTA: Em prod, usaríamos as mesmas funções de validação.
                payload_dict = await auth_service.verify_token(token)
                if not payload_dict:
                    pd = jwt.decode(token, SUPABASE_JWT_SECRET_BIN, algorithms=["HS256"], audience="authenticated")
                    user_id_ws = pd.get("sub")
                else:
                    user_id_ws = payload_dict.get("sub")
                
                # Busca Org (Usa Cache)
                if user_id_ws in org_cache:
                    org_id_ws = org_cache[user_id_ws].organization_id
                else:
                    # Fallback DB
                    async with AsyncSessionLocal() as db:
                        result = await db.execute(select(OrganizationMember.organization_id).where(OrganizationMember.user_id == user_id_ws).limit(1))
                        row = result.first()
                        if row: org_id_ws = row.organization_id

            except Exception as e:
                logger.warning(f"WS auth failed: job={job_id} err={e}")
                await websocket.close(code=1008, reason="Unauthorized")
                return

        if not user_id_ws or not org_id_ws:
            logger.warning(f"WS no identity/org resolved: job={job_id}")
            await websocket.close(code=1008, reason="Identity not found")
            return

        logger.info(f"WS authenticated: job={job_id} user={user_id_ws} org={org_id_ws}")

        # ── 3. Verifica ownership do job (Baseado na Org) ────────
        try:
            job = await job_repo.get(job_id, organization_id=org_id_ws)
            if job and job.get("organization_id") != org_id_ws and user_id_ws != "api_key_user":
                logger.warning(f"WS tenant mismatch: job={job_id} client_org={org_id_ws}")
                await websocket.close(code=1008, reason="Tenant mismatch")
                return
        except Exception as e:
            logger.warning(f"WS job lookup failed (non-fatal): {e}")
            # Não fecha — scan pode ainda não ter criado o job no Redis

        # ── 4. Subscribe no canal Redis ──────────────────────────
        channel = _ws_channel(job_id)
        try:
            redis_conn = get_redis()
            pubsub = redis_conn.pubsub()
            await pubsub.subscribe(channel)
            logger.info(f"WS subscribed: channel={channel}")
        except Exception as e:
            logger.error(f"WS redis subscribe failed: {e}")
            await websocket.close(code=1011, reason="Redis unavailable")
            return

        # ── 5. Confirmação de canal e loop de polling ─────────────
        await websocket.send_text(
            json.dumps({"type": "log", "message": f"[RADIO] Canal ativo: {channel}"})
        )

        last_ping = asyncio.get_event_loop().time()
        PING_INTERVAL = 20.0   # heartbeat a cada 20s
        POLL_SLEEP   = 0.2     # polling a cada 200ms

        logger.info(f"WS entering poll loop: job={job_id}")

        while True:
            # — Polling de mensagens do Redis —
            try:
                msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=0.1)
            except Exception as e:
                logger.error(f"WS pubsub get_message error: {e}")
                break

            if msg and msg.get("type") == "message":
                data = msg["data"]
                if isinstance(data, bytes):
                    data = data.decode("utf-8")
                logger.debug(f"WS forwarding msg: {data[:80]}")
                try:
                    await websocket.send_text(data)
                except Exception as e:
                    logger.info(f"WS send failed (client disconnected?): {e}")
                    break

            # — Heartbeat —
            now = asyncio.get_event_loop().time()
            if now - last_ping >= PING_INTERVAL:
                try:
                    await websocket.send_json({"type": "ping"})
                    last_ping = now
                except Exception as e:
                    logger.info(f"WS heartbeat failed: {e}")
                    break

            await asyncio.sleep(POLL_SLEEP)

        logger.info(f"WS poll loop ended normally: job={job_id}")

    except WebSocketDisconnect as e:
        logger.info(f"WS client disconnected: job={job_id} code={e.code}")
    except Exception as e:
        logger.exception(f"WS crash: job={job_id} error={e}")
        try:
            await websocket.close(code=1011, reason=f"Server error: {str(e)[:50]}")
        except Exception:
            logger.warning(f"WS failed to send close frame: job={job_id}")
    finally:
        # Cleanup connection counter
        _ws_connections[client_ip] = max(0, _ws_connections.get(client_ip, 0) - 1)
        if pubsub:
            try:
                await pubsub.unsubscribe(channel)
                await pubsub.aclose()
            except Exception:
                pass
        logger.info(f"WS cleanup done: job={job_id}")




async def _cleanup_loop():
    """Loop de limpeza de jobs expirados (roda a cada 10 minutos)."""
    while True:
        await asyncio.sleep(600)
        try:
            await job_repo.cleanup_expired()
        except Exception:
            pass


# --- Billing Endpoints ---

class SubscribeRequest(BaseModel):
    plan: str # "pro" or "enterprise"

@app.post("/api/billing/subscribe")
async def subscribe(
    req: SubscribeRequest,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db)
):
    """Cria sessão de checkout do Stripe."""
    # Price IDs deveriam vir de env vars
    price_map = {
        "pro": os.getenv("STRIPE_PRICE_PRO", "price_1..."),
        "enterprise": os.getenv("STRIPE_PRICE_ENT", "price_2...")
    }
    price_id = price_map.get(req.plan)
    if not price_id:
        raise HTTPException(status_code=400, detail="Plano inválido")
    
    # Reconstrói URLs base baseadas no request para funcionar em qualquer host (local ou prod)
    base_url = f"{request.url.scheme}://{request.url.netloc}"
    
    checkout_url = await create_checkout_session(
        organization_id=auth.organization_id,
        price_id=price_id,
        success_url=f"{base_url}/dashboard.html?payment=success",
        cancel_url=f"{base_url}/dashboard.html?payment=cancel"
    )
    return {"url": checkout_url}

@app.post("/api/billing/webhook")
async def stripe_webhook(
    request: Request,
    stripe_signature: str = Header(None, alias="stripe-signature"),
    db: AsyncSession = Depends(get_db)
):
    """Webhook do Stripe para processar pagamentos."""
    body = await request.body()
    success = await handle_stripe_webhook(body, stripe_signature, db)
    if success:
        return {"status": "ok"}
    return JSONResponse(status_code=400, content={"status": "error"})

# ═══════════════════════════════════════════════════════════════
# ORGANIZATION & MEMBERS ENDPOINTS
# ═══════════════════════════════════════════════════════════════

@app.get("/api/org/current")
async def get_current_org(
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db)
):
    """Retorna detalhes da organização atual, incluindo plano e uso."""
    # Busca Org
    stmt_org = select(Organization).where(Organization.id == auth.organization_id)
    res_org = await db.execute(stmt_org)
    org = res_org.scalar_one_or_none()
    if not org: raise HTTPException(status_code=404, detail="Organization not found")

    # Busca Subscription e Usage
    from apiscanner.core.billing_logic import PLAN_LIMITS
    stmt_sub = select(Subscription).where(Subscription.organization_id == auth.organization_id)
    res_sub = await db.execute(stmt_sub)
    sub = res_sub.scalar_one_or_none()
    
    stmt_usage = select(PlanUsage).where(PlanUsage.organization_id == auth.organization_id)
    res_usage = await db.execute(stmt_usage)
    usage = res_usage.scalar_one_or_none()

    plan = sub.plan if sub else "free"
    count = usage.scans_count if usage else 0
    limit = PLAN_LIMITS.get(plan, 5)

    return {
        "id": org.id,
        "name": org.name,
        "owner_id": org.owner_id,
        "plan": plan,
        "usage": {
            "scans_count": count,
            "scans_limit": limit,
            "percent": round((count / limit) * 100, 1) if limit > 0 else 0
        }
    }

@app.get("/api/org/members")
async def list_members(
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db)
):
    """Lista todos os membros da organização."""
    stmt = select(OrganizationMember).where(OrganizationMember.organization_id == auth.organization_id)
    result = await db.execute(stmt)
    members = result.scalars().all()
    return [{"user_id": m.user_id, "role": m.role} for m in members]

class AddMemberRequest(BaseModel):
    user_id: str
    role: str = "member"

@app.post("/api/org/members")
async def add_member(
    req: AddMemberRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db)
):
    """Adiciona um membro à organização (Apenas Admins)."""
    if auth.role != "admin":
        raise HTTPException(status_code=403, detail="Apenas administradores podem gerenciar membros")
    
    # Verifica se já existe
    stmt = select(OrganizationMember).where(
        OrganizationMember.organization_id == auth.organization_id,
        OrganizationMember.user_id == req.user_id
    )
    res = await db.execute(stmt)
    if res.first():
        raise HTTPException(status_code=400, detail="Usuário já é membro desta organização")

    new_member = OrganizationMember(
        organization_id=auth.organization_id,
        user_id=req.user_id,
        role=req.role
    )
    db.add(new_member)
    await db.commit()
    return {"message": "Membro adicionado com sucesso"}

@app.delete("/api/org/members/{member_id}")
async def remove_member(
    member_id: str,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db)
):
    """Remove um membro da organização."""
    if auth.role != "admin":
        raise HTTPException(status_code=403, detail="Apenas administradores podem gerenciar membros")
    
    if member_id == auth.user_id:
        raise HTTPException(status_code=400, detail="Você não pode se remover da própria organização")

    stmt = select(OrganizationMember).where(
        OrganizationMember.organization_id == auth.organization_id,
        OrganizationMember.user_id == member_id
    )
    res = await db.execute(stmt)
    member = res.scalar_one_or_none()
    if not member:
        raise HTTPException(status_code=404, detail="Membro não encontrado")

    await db.delete(member)
    await db.commit()
    return {"message": "Membro removido"}

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
