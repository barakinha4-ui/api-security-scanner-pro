"""
api.py — REST API for API Security Scanner Pro
Provides endpoints to trigger, monitor and retrieve scan results.
"""
import uuid
import asyncio
from typing import List, Optional, Dict
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from core.engine import AsyncEngine
from core.models import ScanResult
from scanner import Scanner

app = FastAPI(title="API Security Scanner Pro API")

# Enable CORS for the dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for scan jobs
# In a real enterprise app, this would be Redis/Database
scans: Dict[str, Dict] = {}

class ScanRequest(BaseModel):
    target: str
    scan_type: str = "full"
    auth: Optional[str] = None
    auth_attacker: Optional[str] = None
    threads: int = 20

async def run_scan_task(scan_id: str, req: ScanRequest):
    print(f"DEBUG: Starting scan task {scan_id} for {req.target}")
    scans[scan_id]["status"] = "running"
    
    headers = {}
    if req.auth:
        headers["Authorization"] = req.auth if " " in req.auth else f"Bearer {req.auth}"

    engine = AsyncEngine(
        concurrency=req.threads,
        headers=headers
    )
    
    attacker_val = None
    if req.auth_attacker:
        attacker_val = req.auth_attacker if " " in req.auth_attacker else f"Bearer {req.auth_attacker}"

    config = {
        "auth_attacker": attacker_val,
        "verbose": True
    }

    print(f"DEBUG: Instantiating Scanner for {req.target}")
    scanner = Scanner(
        target=req.target,
        engine=engine,
        scan_type=req.scan_type,
        config=config
    )

    try:
        print(f"DEBUG: Running Scanner...")
        async with engine:
            result = await scanner.run()
            print(f"DEBUG: Scan {scan_id} completed with {len(result.findings)} findings")
            scans[scan_id]["status"] = "completed"
            scans[scan_id]["result"] = result.to_dict()
    except Exception as e:
        print(f"DEBUG: Scan {scan_id} failed: {e}")
        scans[scan_id]["status"] = "failed"
        scans[scan_id]["error"] = str(e)

@app.post("/scans")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())[:8].upper()
    scans[scan_id] = {
        "id": scan_id,
        "status": "queued",
        "target": req.target,
        "result": None
    }
    background_tasks.add_task(run_scan_task, scan_id, req)
    return {"scan_id": scan_id, "status": "queued"}

@app.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scans[scan_id]

@app.get("/scans")
async def list_scans():
    return list(scans.values())

@app.get("/health")
async def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
