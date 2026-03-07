import os
import json
import uuid
import logging
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional

from jose import jwt, JWTError
from pydantic import BaseModel, ValidationError

from fastapi import FastAPI, BackgroundTasks, HTTPException, Depends, WebSocket, WebSocketDisconnect, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import PlainTextResponse
from dotenv import load_dotenv
import uvicorn

# ================= Configuration =================
load_dotenv()

API_KEY_SECRET = os.getenv("API_KEY_SECRET", "super-secret-local-key")
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET", "supabase-secret")

app = FastAPI(
    title="SaaS Scanner Pro",
    description="API Security Scanner with async engine and WebSocket live logs",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Em produção: ["https://seu-dominio.com"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# ================= Structured Logging =================
class JSONFormatter(logging.Formatter):
    """Formats logs as JSON for structured aggregation (Elasticsearch, Datadog etc)."""
    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "funcName": record.funcName,
        }
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_obj)

logger = logging.getLogger("app_logger")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logger.addHandler(handler)

# ================= In-Memory State =================
jobs: Dict[str, Dict[str, Any]] = {}
active_connections: Dict[str, List[WebSocket]] = {}

# ================= Models =================
class ScanRequest(BaseModel):
    """Payload for initiating a new security scan."""
    target: str
    ports: List[int] = [22, 80, 443]

class JWTPayload(BaseModel):
    """Pydantic schema for parsing and validating the Supabase JWT."""
    sub: str
    exp: int
    role: Optional[str] = "authenticated"

# ================= Auth Middleware =================
async def verify_access(credentials: HTTPAuthorizationCredentials = Security(security)) -> str:
    """
    Validates either the Local API Key or a Supabase JWT.
    Checks expiration natively through python-jose and Pydantic.
    """
    token = credentials.credentials
    
    # 1. Validate against Environment API Key
    if token == API_KEY_SECRET:
        return "api_key_user"
        
    # 2. Validate against Supabase JWT
    try:
        # jwt.decode automatically validates expiration (exp) if present
        payload_dict = jwt.decode(
            token, 
            SUPABASE_JWT_SECRET, 
            algorithms=["HS256"], 
            options={"verify_aud": False}
        )
        payload = JWTPayload(**payload_dict)
        return payload.sub
        
    except JWTError as e:
        logger.error(f"JWT Validation error: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid token")
    except ValidationError as e:
        logger.error(f"JWT Payload validation error: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid token payload structure")
    except Exception as e:
        logger.error(f"Unexpected Auth Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Auth Error")

# ================= Background Tasks =================
async def execute_scanner_job(job_id: str, request: ScanRequest) -> None:
    """
    Async background task acting as the engine wrapper.
    Transitions statuses and dynamically pushes updates to WebSocket clients.
    """
    try:
        logger.info(f"Starting async scan job {job_id} for target {request.target}")
        # 3a. Update Status
        jobs[job_id]["status"] = "running"
        
        # 2. Fire the asynchronous scan engine (Simulated delay here)
        await asyncio.sleep(3) 

        # 3b. Update status to completed upon success
        jobs[job_id]["status"] = "completed"
        jobs[job_id]["results"] = {"open_ports": request.ports, "findings": ["No critical vulnerabilities."]}
        logger.info(f"Successfully completed scan job {job_id}")
        
    except Exception as e:
        logger.error(f"Scan job {job_id} failed abruptly: {str(e)}")
        jobs[job_id]["status"] = "failed"
        jobs[job_id]["error"] = str(e)
        
    finally:
        # 4. Notify WebSocket if client connected
        if job_id in active_connections:
            message = json.dumps({
                "job_id": job_id, 
                "status": jobs[job_id]["status"],
                "results": jobs[job_id].get("results"),
                "error": jobs[job_id].get("error")
            })
            for ws in active_connections[job_id]:
                asyncio.create_task(ws.send_text(message))

# ================= Memory Cleanup =================
async def cleanup_old_jobs() -> None:
    """Remove jobs finalizados com mais de 1 hora para evitar memory leak."""
    while True:
        try:
            now = datetime.now(timezone.utc)
            to_delete = []
            
            for job_id, job in jobs.items():
                created = datetime.fromisoformat(job["created_at"].replace("Z", "+00:00"))
                if job["status"] in ["completed", "failed"] and (now - created) > timedelta(hours=1):
                    to_delete.append(job_id)
                    
            for job_id in to_delete:
                del jobs[job_id]
                # Limpa conexões WebSocket órfãs
                if job_id in active_connections:
                    del active_connections[job_id]
                    
            if to_delete:
                logger.info(f"Memory Cleanup: Removed {len(to_delete)} old jobs")
            
        except Exception as e:
            logger.error(f"Error in cleanup_old_jobs: {str(e)}")
            
        await asyncio.sleep(300)  # Roda a cada 5 minutos

# Inicia o cleanup ao iniciar o app
@app.on_event("startup")
async def startup_event():
    asyncio.create_task(cleanup_old_jobs())
    logger.info("Application startup: cleanup task scheduled")

# ================= REST Endpoints =================
@app.post("/api/scan", tags=["Scanner"])
async def create_scan(req: ScanRequest, bg_tasks: BackgroundTasks, user_id: str = Depends(verify_access)):
    job_id = str(uuid.uuid4())
    
    # 1. Salva job em dict em memória com status="queued"
    jobs[job_id] = {
        "id": job_id,
        "target": req.target,
        "ports": req.ports,
        "status": "queued",
        "user_id": user_id,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    # 2. Dispara a task de background e engine de scan assíncrona
    bg_tasks.add_task(execute_scanner_job, job_id, req)
    
    logger.info(f"Queued scan job {job_id} for user {user_id}")
    return {"job_id": job_id, "status": "queued"}

@app.get("/api/jobs/{job_id}", tags=["Scanner"])
async def get_job_status(job_id: str, user_id: str = Depends(verify_access)):
    if job_id not in jobs:
        logger.warning(f"User {user_id} requested tracking on non-existent job {job_id}")
        raise HTTPException(status_code=404, detail="Job not found")
        
    job = jobs[job_id]
    
    # Isolation: only the creator or full API KEY can introspect this job
    if job["user_id"] != user_id and user_id != "api_key_user":
        logger.warning(f"Unauthorized introspection attempt by {user_id} on {job_id}")
        raise HTTPException(status_code=403, detail="Not authorized to access this job")
        
    return {
        "job_id": job["id"], 
        "status": job["status"], 
        "target": job["target"]
    }

@app.get("/health", tags=["System"])
async def health_check():
    """Returns application health parameters."""
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.get("/metrics", response_class=PlainTextResponse, tags=["System"])
async def get_metrics():
    """Generates Prometheus formatted metric outputs for active jobs."""
    metrics_lines = []
    
    # Extract only running jobs
    active_jobs = {k: v for k, v in jobs.items() if v["status"] == "running"}
    
    metrics_lines.append("# HELP scanner_active_jobs Number of currently running scan sequences")
    metrics_lines.append("# TYPE scanner_active_jobs Gauge")
    
    if not active_jobs:
        metrics_lines.append('scanner_active_jobs 0')
    else:
        for j_id in active_jobs:
            metrics_lines.append(f'scanner_active_jobs {{job_id="{j_id}"}} 1')
            
    return "\n".join(metrics_lines) + "\n"

# ================= WebSocket Endpoint =================
@app.websocket("/ws/logs/{job_id}")
async def websocket_logs(websocket: WebSocket, job_id: str):
    """
    WebSocket endpoint com autenticação JWT obrigatória no handshake.
    Fecha conexão com code 1008 se token inválido (Policy Violation).
    """
    try:
        # 1. Aguarda primeira mensagem com token
        auth_message = await asyncio.wait_for(websocket.receive_text(), timeout=10.0)
        auth_data = json.loads(auth_message)
        
        if "token" not in auth_data:
            await websocket.close(code=1008, reason="Missing token")
            return
            
        token = auth_data["token"]
        
        # 2. Valida token (mesma lógica do verify_access)
        user_id = None
        
        # Check API Key first
        if token == API_KEY_SECRET:
            user_id = "api_key_user"
        else:
            try:
                payload_dict = jwt.decode(token, SUPABASE_JWT_SECRET, algorithms=["HS256"], options={"verify_aud": False})
                payload = JWTPayload(**payload_dict)
                user_id = payload.sub
            except (JWTError, ValidationError):
                logger.warning(f"WebSocket auth failed for job {job_id}")
                await websocket.close(code=1008, reason="Invalid token")
                return
        
        # 3. Verifica se usuário tem acesso ao job
        if job_id in jobs and jobs[job_id]["user_id"] != user_id and user_id != "api_key_user":
            logger.warning(f"User {user_id} tried to access unauthorized job {job_id}")
            await websocket.close(code=1008, reason="Unauthorized")
            return
            
        # 4. Aceita conexão e registra cliente
        await websocket.accept()
        
        if job_id not in active_connections:
            active_connections[job_id] = []
        active_connections[job_id].append(websocket)
        
        logger.info(f"WebSocket connected for job {job_id} by user {user_id}")
        
        # 5. Mantém conexão viva (heartbeats são enviados pelo broadcaster)
        while True:
            # Opcional: receber mensagens do cliente (ex: pause/resume)
            await websocket.receive_text()
            
    except asyncio.TimeoutError:
        await websocket.close(code=1008, reason="Auth timeout")
    except WebSocketDisconnect:
        if job_id in active_connections and websocket in active_connections[job_id]:
            active_connections[job_id].remove(websocket)
            if not active_connections[job_id]:
                del active_connections[job_id]
        logger.info(f"WebSocket disconnected for job {job_id}")
    except Exception as e:
        logger.error(f"WebSocket error for job {job_id}: {str(e)}")
        try:
            await websocket.close(code=1011, reason="Internal error")
        except:
            pass

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
