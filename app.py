import os
import uuid
import asyncio
from datetime import datetime
from typing import Dict, Any, Optional

from fastapi import FastAPI, BackgroundTasks, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import uvicorn
import jwt # For Supabase Auth verification
from dotenv import load_dotenv

# Ensure the scanner source path is accessible
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src", "apiscanner"))

from src.apiscanner.core.engine import AsyncEngine
from src.apiscanner.scanner import Scanner
from src.apiscanner.scanner_config import ScannerConfig

load_dotenv()

# ================= Configuration =================
app = FastAPI(title="API Security Scanner - SaaS Backend", version="1.0.0")
security = HTTPBearer()

SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET", "")
LOCAL_API_KEY = os.getenv("API_KEY_SECRET", "super-secret-local-key")

# In-memory storage for MVP Job Queue (Replace with Redis/Celery for prod)
jobs: Dict[str, Dict[str, Any]] = {}
active_connections: Dict[str, list[WebSocket]] = {}

# ================= Models =================
class ScanRequest(BaseModel):
    target: str
    scan_type: str = "full"
    threads: int = 20

# ================= Auth Guard =================
def verify_access(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verifies either a Local API Key or a valid Supabase JWT"""
    token = credentials.credentials
    
    # 1. Check Local Static API Key
    if token == LOCAL_API_KEY:
        return "service_role"
        
    # 2. Check Supabase JWT
    if not SUPABASE_JWT_SECRET:
        raise HTTPException(status_code=401, detail="Invalid API Key. Supabase not configured.")
        
    try:
        payload = jwt.decode(token, SUPABASE_JWT_SECRET, algorithms=["HS256"], audience="authenticated")
        return payload.get("sub")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid Token")

# ================= Background Task =================
async def execute_scanner_job(job_id: str, req: ScanRequest):
    jobs[job_id]["status"] = "running"
    
    async def on_finding(finding):
        # Callback pushes live findings to clients
        data = finding.to_dict()
        jobs[job_id]["findings"].append(data)
        
        if job_id in active_connections:
            import json
            msg = json.dumps({"type": "finding", "data": data})
            for ws in active_connections[job_id]:
                try:
                    await ws.send_text(msg)
                except:
                    pass

    # Setup Scanner Engine
    config = ScannerConfig(max_concurrency=req.threads)
    engine = AsyncEngine(concurrency=req.threads, timeout=5)
    
    scanner = Scanner(
        target=req.target,
        engine=engine,
        scan_type=req.scan_type,
        config=config,
        on_finding=on_finding
    )
    
    try:
        async with engine:
            result = await scanner.run()
            jobs[job_id]["status"] = "completed"
            jobs[job_id]["report"] = result.summary
            
            # Send completion signal via WS
            if job_id in active_connections:
                import json
                msg = json.dumps({"type": "status", "data": "completed"})
                for ws in active_connections[job_id]:
                    try:
                        await ws.send_text(msg)
                    except:
                        pass
    except Exception as e:
        jobs[job_id]["status"] = "failed"
        jobs[job_id]["error"] = str(e)


# ================= REST Endpoints =================
@app.post("/api/scan", tags=["Scanner"])
async def trigger_scan(req: ScanRequest, bg_tasks: BackgroundTasks, user_id: str = Depends(verify_access)):
    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        "id": job_id,
        "target": req.target,
        "status": "queued",
        "created_at": datetime.utcnow().isoformat(),
        "findings": [],
        "report": None,
        "user_id": user_id
    }
    
    bg_tasks.add_task(execute_scanner_job, job_id, req)
    return {"job_id": job_id, "status": "queued", "message": "Scan dispatched in background."}

@app.get("/api/status/{job_id}", tags=["Scanner"])
async def get_scan_status(job_id: str, user_id: str = Depends(verify_access)):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
        
    job = jobs[job_id]
    if job["user_id"] != user_id and user_id != "service_role":
        raise HTTPException(status_code=403, detail="Not authorized to view this job")
        
    return {
        "status": job["status"],
        "target": job["target"],
        "findings_count": len(job["findings"]),
        "report": job["report"]
    }

# ================= WebSocket Endpoints =================
@app.websocket("/ws/logs/{job_id}")
async def websocket_logs(websocket: WebSocket, job_id: str):
    await websocket.accept()
    
    if job_id not in jobs:
        await websocket.close(code=1008)
        return
        
    # Register connection
    if job_id not in active_connections:
        active_connections[job_id] = []
    active_connections[job_id].append(websocket)
    
    try:
        # Replay past findings to the new connection
        for f in jobs[job_id].get("findings", []):
            import json
            await websocket.send_text(json.dumps({"type": "finding", "data": f}))
            
        while True:
            # Keep alive loop
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections[job_id].remove(websocket)
        if not active_connections[job_id]:
            del active_connections[job_id]

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
