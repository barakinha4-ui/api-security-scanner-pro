"""
redis_config.py — Configuração e pool de conexão com Redis
Usa redis.asyncio para operações assíncronas (redis-py >= 4.5.0)
"""
import os
import redis.asyncio as aioredis
from redis.asyncio.connection import ConnectionPool

# ── Parâmetros de conexão (lidos do ambiente) ──────────────────
REDIS_HOST     = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT     = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB       = int(os.getenv("REDIS_DB", 0))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)

# ── TTL (segundos) para jobs finalizados ───────────────────────
JOB_TTL = int(os.getenv("JOB_TTL", 3600))   # 1 hora

# ── Pool de conexão compartilhado ──────────────────────────────
#    max_connections=50 para suportar múltiplos workers (gunicorn)
_pool: ConnectionPool | None = None


def get_pool() -> ConnectionPool:
    """Retorna (ou cria) o pool singleton de conexões Redis."""
    global _pool
    if _pool is None:
        _pool = aioredis.ConnectionPool(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            password=REDIS_PASSWORD,
            max_connections=50,
            decode_responses=True,   # retorna strings Python (não bytes)
        )
    return _pool


def get_redis() -> aioredis.Redis:
    """Retorna um cliente Redis usando o pool global."""
    return aioredis.Redis(connection_pool=get_pool())


async def ping_redis() -> tuple[bool, float]:
    """
    Verifica disponibilidade do Redis.
    Retorna (ok: bool, latency_ms: float).
    """
    import time
    try:
        client = get_redis()
        t0 = time.perf_counter()
        await client.ping()
        latency = (time.perf_counter() - t0) * 1000
        return True, round(latency, 2)
    except Exception:
        return False, -1.0
