"""
tests/mock_target.py — Servidor mock para testes sem dependências externas

Expõe endpoints que simulam comportamentos reais de APIs:
  • GET /          → 200 OK (resposta rápida)
  • GET /slow      → 200 OK (delay de 2s — simula serviço lento)
  • GET /flaky     → 50% 200, 50% 500 (simula instabilidade)
  • GET /auth      → valida Bearer token simples
  • GET /api/users → lista de usuários fake (BOLA simulado)
  • POST /api/data → aceita JSON e retorna 201

Uso:
    # Inicia servidor mock na porta 9000
    python tests/mock_target.py

    # Ou via uvicorn diretamente
    uvicorn tests.mock_target:app --port 9000 --reload
"""
import asyncio
import random
import time
import os
import sys

# Garante imports relativos corretos
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

app = FastAPI(title="Mock Target API", version="1.0.0")

# ── Contador de requisições (para verificar volume sob carga) ──
_stats = {"requests": 0, "errors": 0}


@app.get("/")
async def root():
    """Resposta rápida — simula endpoint saudável."""
    _stats["requests"] += 1
    return {"status": "ok", "message": "Mock Target API", "ts": time.time()}


@app.get("/slow")
async def slow_endpoint():
    """Simula serviço lento (2s) — testa timeouts do scanner."""
    _stats["requests"] += 1
    await asyncio.sleep(2)
    return {"status": "ok", "message": "Resposta lenta", "delay_s": 2}


@app.get("/flaky")
async def flaky_endpoint():
    """Retorna 500 em ~50% das requisições — testa resiliência."""
    _stats["requests"] += 1
    if random.random() < 0.5:
        _stats["errors"] += 1
        raise HTTPException(status_code=500, detail="Random failure (flaky endpoint)")
    return {"status": "ok", "message": "Você teve sorte desta vez"}


@app.get("/auth")
async def auth_endpoint(authorization: str = Header(default=None)):
    """Valida Bearer token simples — simula endpoint autenticado."""
    _stats["requests"] += 1
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    return {"status": "authenticated", "token_prefix": authorization[:16] + "..."}


@app.get("/api/users")
async def list_users():
    """Lista de usuários fake — simula BOLA/IDOR vulnerability."""
    _stats["requests"] += 1
    users = [
        {"id": i, "name": f"User {i}", "email": f"user{i}@example.com", "role": "user"}
        for i in range(1, 11)
    ]
    return {"users": users, "total": len(users)}


@app.get("/api/users/{user_id}")
async def get_user(user_id: int):
    """Endpoint com IDOR — não valida autorização."""
    _stats["requests"] += 1
    if user_id < 1 or user_id > 100:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "id":    user_id,
        "name":  f"User {user_id}",
        "email": f"user{user_id}@example.com",
        "role":  "admin" if user_id == 1 else "user",
        "token": f"secret-token-{user_id}",   # Dado sensível exposto intencionalmente
    }


@app.post("/api/data")
async def create_data(body: dict):
    """Aceita JSON e retorna 201 — simula endpoint de criação."""
    _stats["requests"] += 1
    return JSONResponse(
        status_code=201,
        content={"status": "created", "echo": body, "id": random.randint(1000, 9999)},
    )


@app.get("/admin/stats")
async def stats():
    """Expõe estatísticas internas do mock (sem auth) — vulnerabilidade intencional."""
    return _stats


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("MOCK_PORT", 9000))
    print(f"🎯 Mock Target rodando em http://localhost:{port}")
    uvicorn.run("tests.mock_target:app", host="0.0.0.0", port=port, reload=False)
