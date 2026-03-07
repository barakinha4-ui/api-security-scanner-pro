# app.py - SaaS Wrapper com Scanner Real Integrado + Redis
# Porta: 8000 | Auth: JWT/API Key | Engine: AsyncEngine + Scanner
# Storage: Redis (persistência) | WS: Pub/Sub (multi-instância)

import os
import sys
import json
import uuid
import logging
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

# Adiciona src/apiscanner ao path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_PATH = os.path.join(BASE_DIR, "src", "apiscanner")
if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)

from pydantic import BaseModel, ValidationError
from jose import jwt, JWTError
from dotenv import load_dotenv
import uvicorn

from fastapi import FastAPI, BackgroundTasks, HTTPException, Depends, WebSocket, WebSocketDisconnect, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import PlainTextResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from redis.exceptions import RedisError
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from core.metrics import (
    SCANNER_JOBS_TOTAL, SCANNER_ACTIVE_JOBS, SCANNER_FINDINGS_TOTAL,
    SCAN_PHASE_DURATION, RATE_LIMITED_REQS_TOTAL, ACTIVE_SCANS_PER_TARGET,
    HTTP_REQUEST_DURATION
)
import time

# ── Scanner engine ──────────────────────────────────────────
try:
    from core.engine import AsyncEngine
    from core.models import ScanResult, Finding, Severity
    from scanner import Scanner
    SCANNER_AVAILABLE = True
except ImportError as e:
    SCANNER_AVAILABLE = False
    print(f"⚠️  Warning: apiscanner modules not found: {e}")

# ── Redis ────────────────────────────────────────────────────
from redis_config import get_redis, ping_redis
from repository.job_repository import JobRepository
import redis.asyncio as aioredis

# ── Configuration ────────────────────────────────────────────
load_dotenv()

API_KEY_SECRET      = os.getenv("API_KEY_SECRET", "super-secret-local-key")
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET", "supabase-secret")
SCAN_TIMEOUT        = int(os.getenv("SCAN_TIMEOUT", "300"))
MAX_CONCURRENCY     = int(os.getenv("MAX_CONCURRENCY", "20"))

# ── FastAPI App ──────────────────────────────────────────────
app = FastAPI(
    title="SaaS Scanner Pro",
    description="API Security Scanner — Redis-backed, WebSocket Pub/Sub, async engine",
    version="2.0.0",
    docs_url="/docs" if os.getenv("ENV") != "production" else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security      = HTTPBearer()
job_repo      = JobRepository()          # Singleton do repositório Redis

# ── Structured Logging ───────────────────────────────────────
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
_handler = logging.StreamHandler()
_handler.setFormatter(JSONFormatter())
logger.addHandler(_handler)

# ── Prometheus Metrics ───────────────────────────────────────

@app.middleware("http")
async def prometheus_latency_middleware(request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time
    # Ignora metrics no histogram de latência
    if request.url.path != "/metrics":
        HTTP_REQUEST_DURATION.labels(
            method=request.method,
            endpoint=request.url.path
        ).observe(duration)
    
    return response


# ── Rota de métricas para o Prometheus ──────────────────────
@app.get("/metrics", tags=["Monitoramento"])
async def metrics():
    """Expondo métricas no formato Prometheus."""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )

# ── Models ───────────────────────────────────────────────────
class ScanRequest(BaseModel):
    target:      str
    ports:       List[int]       = [22, 80, 443]
    timeout:     Optional[int]   = None
    concurrency: Optional[int]   = None
    scan_type:   Optional[str]   = "full"
    plugins:     Optional[List[str]] = None

class JWTPayload(BaseModel):
    sub:  str
    exp:  int
    role: Optional[str] = "authenticated"

    def is_valid(self) -> bool:
        return datetime.now(timezone.utc).timestamp() < self.exp


# ── Redis helper: 503 quando indisponível ────────────────────
def _redis_503() -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"detail": "Redis indisponível — tente novamente em instantes"},
        headers={"Retry-After": "10"},
    )


# ── Auth ─────────────────────────────────────────────────────
async def verify_access(credentials: HTTPAuthorizationCredentials = Security(security)) -> str:
    token = credentials.credentials

    if token == API_KEY_SECRET:
        return "api_key_user"

    try:
        payload_dict = jwt.decode(token, SUPABASE_JWT_SECRET, algorithms=["HS256"], options={"verify_aud": False})
        payload = JWTPayload(**payload_dict)
        if not payload.is_valid():
            raise HTTPException(status_code=401, detail="Token expired")
        return payload.sub
    except (JWTError, ValidationError) as e:
        logger.error(f"JWT validation failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        logger.error(f"Unexpected auth error: {e}")
        raise HTTPException(status_code=500, detail="Internal auth error")


# ═══════════════════════════════════════════════════════════════
# WEBSOCKET PUB/SUB — Substitui active_connections dict
# Canal: "ws:job:{job_id}" no Redis
# Cada instância do app faz subscribe neste canal e repassa ao WS
# ═══════════════════════════════════════════════════════════════
def _ws_channel(job_id: str) -> str:
    return f"ws:job:{job_id}"

async def _publish(job_id: str, payload: dict) -> None:
    """Publica payload JSON no canal Pub/Sub do job."""
    try:
        r = get_redis()
        await r.publish(_ws_channel(job_id), json.dumps(payload))
    except RedisError as e:
        logger.warning(f"Falha ao publicar no canal Pub/Sub do job {job_id}: {e}")


# ═══════════════════════════════════════════════════════════════
# BACKGROUND TASK — Executa scan real e persiste no Redis
# ═══════════════════════════════════════════════════════════════
async def execute_scanner_job(job_id: str, request: ScanRequest, user_id: str) -> None:
    if not SCANNER_AVAILABLE:
        msg = "Scanner engine not installed"
        logger.error(msg, extra={"job_id": job_id})
        await job_repo.update(job_id, {"status": "failed", "error": msg})
        await _publish(job_id, {"job_id": job_id, "status": "failed", "error": msg})
        SCANNER_JOBS_TOTAL.labels(status="failed").inc()
        return

    try:
        SCANNER_ACTIVE_JOBS.inc()
        logger.info("Starting scan job", extra={"job_id": job_id, "target": request.target})
        await job_repo.update(job_id, {
            "status":     "running",
            "started_at": datetime.now(timezone.utc).isoformat()
        })
        SCANNER_JOBS_TOTAL.labels(status="running").inc()
        await _publish(job_id, {"job_id": job_id, "status": "running", "target": request.target})

        # ── Callback de finding em tempo real ──────────────
        async def on_finding_callback(finding: Finding):
            finding_dict = finding.to_dict()
            sev = (finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)).upper()
            
            # Incrementa métrica Prometheus
            SCANNER_FINDINGS_TOTAL.labels(severity=sev).inc()

            # Persiste o finding no Redis atomicamente
            await job_repo.append_finding(job_id, finding_dict)
            # Propaga via Pub/Sub para todos os WebSockets conectados
            await _publish(job_id, {
                "job_id":    job_id,
                "type":      "finding",
                "data":      finding_dict,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
            logger.info(
                f"Finding: {finding.severity} — {finding.title}",
                extra={"job_id": job_id}
            )

        # ── Callback de log em tempo real ──────────────────
        async def on_log_callback(msg: str):
            await _publish(job_id, {
                "job_id":    job_id,
                "type":      "log",
                "message":   msg,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })

        # ── Callback de eventos de segurança ───────────────
        async def on_security_event_callback(evt: dict):
            await _publish(job_id, {
                "job_id":    job_id,
                "type":      "security_event",
                "host":      urlparse(evt["url"]).hostname,
                "severity":  "INFO",
                "title":     f"🛡️ Request Blocked: {evt['reason']}",
                "message":   f"{evt.get('method', 'GET')} {evt['url']}",
                "category":  evt["category"],
                "timestamp": datetime.now(timezone.utc).isoformat()
            })

        # ── Executa o scanner ──────────────────────────────
        async with AsyncEngine(
            concurrency=request.concurrency or MAX_CONCURRENCY,
            timeout=request.timeout or SCAN_TIMEOUT,
            on_security_event=on_security_event_callback
        ) as engine:
            scanner = Scanner(
                target=request.target,
                engine=engine,
                scan_type=request.scan_type or "full",
                plugins=request.plugins,
                on_finding=on_finding_callback,
                on_log=on_log_callback
            )
            result: ScanResult = await scanner.run()
            summary = result.summary

        # ── Persiste resultado final ───────────────────────
        await job_repo.update(job_id, {
            "status":       "completed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "summary":      summary,
        })
        SCANNER_JOBS_TOTAL.labels(status="completed").inc()
        await _publish(job_id, {
            "job_id":  job_id,
            "status":  "completed",
            "summary": summary
        })
        logger.info("Scan completed", extra={"job_id": job_id})

    except asyncio.TimeoutError:
        logger.error("Scan timed out", extra={"job_id": job_id})
        await job_repo.update(job_id, {"status": "failed", "error": "Scan timeout exceeded"})
        SCANNER_JOBS_TOTAL.labels(status="failed").inc()
        await _publish(job_id, {"job_id": job_id, "status": "failed", "error": "Timeout"})

    except RedisError as e:
        logger.error(f"Redis error durante scan: {e}", extra={"job_id": job_id})
        # Não conseguimos persistir, mas o scan pode ter rodado

    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True, extra={"job_id": job_id})
        try:
            await job_repo.update(job_id, {"status": "failed", "error": str(e)})
            SCANNER_JOBS_TOTAL.labels(status="failed").inc()
        except RedisError:
            pass
        await _publish(job_id, {"job_id": job_id, "status": "failed", "error": str(e)})
    finally:
        SCANNER_ACTIVE_JOBS.dec()


# ═══════════════════════════════════════════════════════════════
# REST ENDPOINTS
# ═══════════════════════════════════════════════════════════════

@app.post("/api/scan", tags=["Scanner"], status_code=202)
async def create_scan(req: ScanRequest, bg_tasks: BackgroundTasks, user_id: str = Depends(verify_access)):
    """Cria e enfileira um novo job de scan."""
    job_id = str(uuid.uuid4())
    job_data = {
        "id":         job_id,
        "target":     req.target,
        "ports":      req.ports,
        "status":     "queued",
        "user_id":    user_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "findings":   [],
    }

    try:
        await job_repo.create(job_id, job_data)
        SCANNER_JOBS_TOTAL.labels(status="queued").inc()
    except RedisError:
        return _redis_503()

    bg_tasks.add_task(execute_scanner_job, job_id, req, user_id)
    logger.info("Scan job queued", extra={"job_id": job_id, "user_id": user_id})
    return {"job_id": job_id, "status": "queued", "message": "Scan initiated"}


@app.get("/api/jobs", tags=["Scanner"])
async def list_jobs(limit: int = 50, user_id: str = Depends(verify_access)):
    """Lista os últimos `limit` jobs do usuário autenticado."""
    try:
        jobs = await job_repo.list_by_user(user_id, limit=limit)
    except RedisError:
        return _redis_503()

    return {
        "jobs": [
            {
                "job_id":     j.get("id"),
                "target":     j.get("target"),
                "status":     j.get("status"),
                "created_at": j.get("created_at"),
            }
            for j in jobs
        ],
        "total": len(jobs),
    }


@app.get("/api/jobs/{job_id}", tags=["Scanner"])
async def get_job_status(job_id: str, user_id: str = Depends(verify_access)):
    """Retorna status atual de um job."""
    try:
        job = await job_repo.get(job_id)
    except RedisError:
        return _redis_503()

    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.get("user_id") != user_id and user_id != "api_key_user":
        raise HTTPException(status_code=403, detail="Not authorized")

    return {
        "job_id":     job.get("id"),
        "status":     job.get("status"),
        "target":     job.get("target"),
        "created_at": job.get("created_at"),
        "summary":    job.get("summary"),
    }


@app.get("/api/jobs/{job_id}/results", tags=["Scanner"])
async def get_job_results(job_id: str, user_id: str = Depends(verify_access)):
    """Retorna resultados completos de um job finalizado."""
    try:
        job = await job_repo.get(job_id)
    except RedisError:
        return _redis_503()

    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.get("user_id") != user_id and user_id != "api_key_user":
        raise HTTPException(status_code=403, detail="Not authorized")

    if job.get("status") not in ("completed", "failed"):
        raise HTTPException(status_code=400, detail="Scan not finished yet")

    return {
        "job_id":   job.get("id"),
        "target":   job.get("target"),
        "status":   job.get("status"),
        "error":    job.get("error"),
        "summary":  job.get("summary"),
        "findings": job.get("findings", []),
    }


@app.get("/api/jobs/{job_id}/export", tags=["Scanner"])
async def export_job(job_id: str, user_id: str = Depends(verify_access)):
    """Exporta JSON completo do job para download."""
    try:
        job = await job_repo.get(job_id)
    except RedisError:
        return _redis_503()

    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.get("user_id") != user_id and user_id != "api_key_user":
        raise HTTPException(status_code=403, detail="Not authorized")

    content = json.dumps(job, ensure_ascii=False, indent=2)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="job_{job_id}.json"'},
    )


@app.delete("/api/jobs/{job_id}", tags=["Scanner"])
async def delete_job(job_id: str, user_id: str = Depends(verify_access)):
    """Remove job do Redis (apenas owner ou api_key_user)."""
    try:
        job = await job_repo.get(job_id)
    except RedisError:
        return _redis_503()

    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.get("user_id") != user_id and user_id != "api_key_user":
        raise HTTPException(status_code=403, detail="Not authorized")

    try:
        await job_repo.delete(job_id, job.get("user_id", user_id))
    except RedisError:
        return _redis_503()

    return {"message": "Job removed", "job_id": job_id}


# ── Health check com Redis ───────────────────────────────────
@app.get("/health", tags=["System"])
async def health_check():
    redis_ok, redis_ms = await ping_redis()
    response = {
        "status":          "ok" if redis_ok else "degraded",
        "timestamp":       datetime.now(timezone.utc).isoformat(),
        "scanner_engine":  "available" if SCANNER_AVAILABLE else "unavailable",
        "redis_status":    "connected" if redis_ok else "disconnected",
        "redis_latency_ms": redis_ms,
    }
    if not redis_ok:
        return JSONResponse(
            status_code=503,
            content=response,
            headers={"Retry-After": "10"},
        )
    return response


# ── Prometheus-style metrics ─────────────────────────────────
@app.get("/metrics", response_class=PlainTextResponse, tags=["System"])
async def get_metrics():
    """Exporta métricas no formato Prometheus (Standard + Custom Redis)."""
    try:
        # Pega métricas do prometheus_client (histograms, active jobs, etc)
        metrics_data = generate_latest().decode("utf-8")
        
        # Pega métricas reais persistidas no Redis (Jobs totais por status)
        stats = await job_repo.get_stats()
        redis_metrics = [
            "# HELP scanner_jobs_total Total jobs by status (from Redis)",
            "# TYPE scanner_jobs_total counter"
        ]
        for status in ("queued", "running", "completed", "failed"):
            val = stats.get(status, 0)
            redis_metrics.append(f'scanner_jobs_total{{status="{status}"}} {val}')
        
        return PlainTextResponse(metrics_data + "\n" + "\n".join(redis_metrics) + "\n", media_type=CONTENT_TYPE_LATEST)
    except Exception as e:
        logger.error(f"Error generating metrics: {e}")
        return PlainTextResponse(f"# Error: {e}", status_code=500)


# ═══════════════════════════════════════════════════════════════
# WEBSOCKET ENDPOINT — Subscribe ao canal Redis Pub/Sub
# Cada instância do app cria um subscriber independente,
# permitindo escalonamento horizontal com múltiplos workers.
# ═══════════════════════════════════════════════════════════════
@app.websocket("/ws/logs/{job_id}")
async def websocket_logs(websocket: WebSocket, job_id: str):
    await websocket.accept()

    try:
        # ── Auth handshake (primeira mensagem deve ser {"token": "..."}) ──
        auth_raw  = await asyncio.wait_for(websocket.receive_text(), timeout=10.0)
        auth_data = json.loads(auth_raw)
        token     = auth_data.get("token", "")

        user_id = None
        if token == API_KEY_SECRET:
            user_id = "api_key_user"
        else:
            try:
                pd = jwt.decode(token, SUPABASE_JWT_SECRET, algorithms=["HS256"], options={"verify_aud": False})
                payload = JWTPayload(**pd)
                if not payload.is_valid():
                    raise ValueError("expired")
                user_id = payload.sub
            except Exception:
                await websocket.close(code=1008, reason="Invalid token")
                return

        # ── Verifica autorização para o job ───────────────
        try:
            job = await job_repo.get(job_id)
        except RedisError:
            await websocket.close(code=1011, reason="Redis unavailable")
            return

        if job and job.get("user_id") != user_id and user_id != "api_key_user":
            await websocket.close(code=1008, reason="Unauthorized for this job")
            return

        logger.info(f"WS connected — subscribing to {_ws_channel(job_id)}", extra={"job_id": job_id})

        # ── Cria subscriber Redis dedicado para este WS ───
        pubsub = get_redis().pubsub()
        await pubsub.subscribe(_ws_channel(job_id))

        async def _forward_messages():
            """Lê mensagens do canal Pub/Sub e envia para o WebSocket."""
            async for msg in pubsub.listen():
                if msg["type"] == "message":
                    try:
                        await websocket.send_text(msg["data"])
                    except Exception:
                        break

        async def _heartbeat():
            """Mantém a conexão viva enviando pings periódicos."""
            try:
                while True:
                    await asyncio.sleep(20)
                    await websocket.send_json({"type": "ping", "timestamp": datetime.now(timezone.utc).isoformat()})
            except Exception:
                pass

        # ── Executa tarefas em background ──────────────
        forward_task   = asyncio.create_task(_forward_messages())
        heartbeat_task = asyncio.create_task(_heartbeat())

        try:
            # Mantém conexão viva; encerra quando cliente desconectar
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect as e:
            logger.info(f"WS disconnected: job_id={job_id}, code={e.code}, reason={e.reason or 'none'}")
        except Exception as e:
            logger.warning(f"WS error during receive: {e}")
        finally:
            forward_task.cancel()
            heartbeat_task.cancel()
            await pubsub.unsubscribe(_ws_channel(job_id))
            await pubsub.close()

    except asyncio.TimeoutError:
        await websocket.close(code=1008, reason="Auth timeout")
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        try:
            await websocket.close(code=1011)
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════
# STARTUP / SHUTDOWN
# ═══════════════════════════════════════════════════════════════
@app.on_event("startup")
async def startup():
    redis_ok, ms = await ping_redis()
    if redis_ok:
        logger.info(f"🚀 SaaS Scanner Pro v2.0 iniciado — Redis OK ({ms}ms)")
    else:
        logger.warning("🚀 SaaS Scanner Pro iniciado — Redis INDISPONÍVEL (modo degraded)")

    # Inicia tarefa periódica de limpeza de índices Redis
    asyncio.create_task(_cleanup_loop())


async def _cleanup_loop():
    """Limpa índices Redis obsoletos a cada 10 minutos."""
    while True:
        await asyncio.sleep(600)
        try:
            removed = await job_repo.cleanup_expired()
            if removed:
                logger.info(f"Cleanup: {removed} entradas de índice removidas")
        except Exception as e:
            logger.error(f"Cleanup error: {e}")


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=os.getenv("ENV") != "production")
