"""
api.py — Secure REST API for API Security Scanner Pro with WebSockets
"""
import os
from dotenv import load_dotenv

# Load environment variables from .env file before anything else
env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), '.env')
load_dotenv(dotenv_path=env_path)

import uuid
import asyncio
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, BackgroundTasks, HTTPException, Header, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import secrets
import json

from .core.engine import AsyncEngine
from .core.models import ScanResult
from scanner import Scanner

# Configuration
API_KEY = os.getenv("SCANNER_API_KEY")
if not API_KEY:
    API_KEY = secrets.token_hex(16)
print(f"[*] DASHBOARD API KEY: {API_KEY}")

app = FastAPI(title="API Security Scanner Pro API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for scan jobs
scans: Dict[str, Dict[str, Any]] = {}

# ─── WebSocket Connection Manager ────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, scan_id: str, websocket: WebSocket):
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(websocket)

    def disconnect(self, scan_id: str, websocket: WebSocket):
        if scan_id in self.active_connections:
            self.active_connections[scan_id].remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast_to_scan(self, scan_id: str, message: dict):
        if scan_id in self.active_connections:
            for connection in self.active_connections[scan_id]:
                try:
                    await connection.send_json(message)
                except Exception:
                    pass

manager = ConnectionManager()

# ─── Auth Dependency ─────────────────────────────────────────────────────────

async def verify_token(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return x_api_key

# ─── Background Tasks ────────────────────────────────────────────────────────

async def cleanup_scans():
    while True:
        now = datetime.now()
        to_delete = []
        for sid, data in scans.items():
            if "created_at" in data and now - data["created_at"] > timedelta(hours=1):
                to_delete.append(sid)
        for sid in to_delete:
            del scans[sid]
        await asyncio.sleep(600)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(cleanup_scans())

class ScanRequest(BaseModel):
    target: str
    scan_type: str = "full"
    auth: Optional[str] = None
    auth_attacker: Optional[str] = None
    threads: int = 20
    encrypt_result: bool = False

from .core.crypto import shield

async def run_scan_task(scan_id: str, req: ScanRequest):
    print(f"[*] Starting scan {scan_id} -> {req.target}")
    scans[scan_id]["status"] = "running"
    
    # WebSocket Update: Scan Started
    await manager.broadcast_to_scan(scan_id, {"type": "status", "data": "running"})

    async def on_finding_callback(finding):
        # Broadcast each finding in real-time
        data = finding.to_dict() if hasattr(finding, "to_dict") else finding
        
        # If encryption is requested, encrypt the whole finding data
        if req.encrypt_result:
            data = {"encrypted": True, "payload": shield.encrypt(json.dumps(data))}

        # Buffer finding for late-connecting WebSocket clients (replay)
        if scan_id in scans:
            scans[scan_id]["findings"].append(data)

        await manager.broadcast_to_scan(scan_id, {
            "type": "finding",
            "data": data
        })

    headers = {}
    if req.auth:
        headers["Authorization"] = req.auth if " " in req.auth else f"Bearer {req.auth}"

    engine = AsyncEngine(
        concurrency=min(req.threads, 200),
        timeout=4,      # 4s timeout — fast enough for most APIs
        delay=0.0,      # No artificial delay
        headers=headers,
        allow_internal=False
    )
    
    attacker_val = None
    if req.auth_attacker:
        attacker_val = req.auth_attacker if " " in req.auth_attacker else f"Bearer {req.auth_attacker}"

    from scanner_config import ScannerConfig
    
    config = ScannerConfig()
    
    scanner = Scanner(
        target=req.target,
        engine=engine,
        scan_type=req.scan_type,
        config=config,
        on_finding=on_finding_callback
    )

    try:
        async with engine:
            result = await scanner.run()
            scans[scan_id]["status"] = "completed"
            
            res_dict = result.to_dict()
            if req.encrypt_result:
                # Encrypt the final result blob
                res_dict = {"encrypted": True, "payload": shield.encrypt(json.dumps(res_dict))}
            
            scans[scan_id]["result"] = res_dict
            await manager.broadcast_to_scan(scan_id, {"type": "status", "data": "completed", "result": res_dict})
    except Exception as e:
        print(f"[!] Scan {scan_id} failed: {e}")
        scans[scan_id]["status"] = "failed"
        scans[scan_id]["error"] = str(e)
        await manager.broadcast_to_scan(scan_id, {"type": "status", "data": "failed", "error": str(e)})

# ─── Endpoints ──────────────────────────────────────────────────────────────

@app.post("/scans", dependencies=[Depends(verify_token)])
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())[:8].upper()
    scans[scan_id] = {
        "id": scan_id,
        "status": "queued",
        "target": req.target,
        "created_at": datetime.now(),
        "result": None,
        "findings": []  # Buffer for replay on late WebSocket connect
    }
    background_tasks.add_task(run_scan_task, scan_id, req)
    return {"scan_id": scan_id, "status": "queued"}

@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    await manager.connect(scan_id, websocket)
    try:
        if scan_id in scans:
            scan_data = scans[scan_id]
            
            # 1. Replay all findings buffered so far (fixes 'static screen' issue)
            for past_finding in scan_data.get("findings", []):
                await websocket.send_json({"type": "finding", "data": past_finding})
            
            # 2. Send current status
            await websocket.send_json({"type": "status", "data": scan_data["status"]})
            
            # 3. If already completed, send the final result immediately
            if scan_data["status"] == "completed" and scan_data.get("result"):
                await websocket.send_json({"type": "status", "data": "completed", "result": scan_data["result"]})
        
        while True:
            data = await websocket.receive_text()
            # Handle client heartbeats or commands if needed
    except WebSocketDisconnect:
        manager.disconnect(scan_id, websocket)

@app.get("/scans/{scan_id}", dependencies=[Depends(verify_token)])
async def get_scan(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scans[scan_id]

@app.get("/scans", dependencies=[Depends(verify_token)])
async def list_scans():
    return [{"id": s["id"], "target": s["target"], "status": s["status"]} for s in scans.values()]

@app.get("/health")
async def health():
    return {"status": "ok", "memory_jobs": len(scans)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
