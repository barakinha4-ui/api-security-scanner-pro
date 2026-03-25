"""
repository/job_repository.py — Repositório assíncrono para jobs no Redis

Estrutura de dados no Redis:
  ┌─ "job:{job_id}"           → Hash  (campos do job)
  ├─ "jobs:user:{user_id}"    → Sorted Set (score = timestamp de criação)
  └─ "stats:jobs"             → Hash  (contadores por status)

Métodos: create, get, update, delete, list_by_user, get_stats, cleanup_expired
"""
import json
import logging
import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import redis.asyncio as aioredis
from redis.asyncio.client import Redis
from redis.exceptions import ConnectionError, TimeoutError, RedisError

from redis_config import get_redis, JOB_TTL

logger = logging.getLogger("job_repository")

# ── Prefixos de chave (Multi-tenant) ────────────────
def _job_key(job_id: str, organization_id: str) -> str:
    return f"job:{organization_id}:{job_id}"

def _org_index_key(organization_id: str) -> str:
    """Índice de jobs por ORG (era por user_id)."""
    return f"jobs:org:{organization_id}"

STATS_KEY = "stats:jobs"

# ── Decorator de retry com backoff exponencial ────────────────
def with_retry(max_retries: int = 3, base_delay: float = 0.2):
    """
    Tenta a operação até max_retries vezes com backoff exponencial.
    Em caso de falha persistente, propaga RedisError.
    """
    def decorator(fn):
        async def wrapper(*args, **kwargs):
            delay = base_delay
            last_exc: Exception | None = None
            for attempt in range(1, max_retries + 1):
                try:
                    return await fn(*args, **kwargs)
                except (ConnectionError, TimeoutError) as exc:
                    last_exc = exc
                    logger.warning(
                        f"Redis retry {attempt}/{max_retries} for {fn.__name__}: {exc}"
                    )
                    await asyncio.sleep(delay)
                    delay *= 2
            raise RedisError(f"Redis operation '{fn.__name__}' failed after {max_retries} retries") from last_exc
        return wrapper
    return decorator


# ── Circuit Breaker simples ───────────────────────────────────
class _CircuitBreaker:
    THRESHOLD   = 5        # erros consecutivos para abrir o circuito
    OPEN_WINDOW = 60.0     # segundos com circuito aberto

    def __init__(self):
        self._errors = 0
        self._opened_at: float | None = None

    def record_success(self):
        self._errors = 0
        self._opened_at = None

    def record_failure(self):
        self._errors += 1
        if self._errors >= self.THRESHOLD:
            import time
            self._opened_at = time.monotonic()
            logger.error("Redis circuit breaker OPENED after %d consecutive errors", self._errors)

    def is_open(self) -> bool:
        if self._opened_at is None:
            return False
        import time
        if time.monotonic() - self._opened_at > self.OPEN_WINDOW:
            logger.warning("Redis circuit breaker HALF-OPEN — tentando reconectar")
            self._opened_at = None
            self._errors = 0
            return False
        return True


_circuit = _CircuitBreaker()


# ─────────────────────────────────────────────────────────────
class JobRepository:
    """
    Repositório assíncrono de jobs usando Redis.
    Todos os métodos são coroutines (async def).
    """

    def __init__(self, redis_client: Redis | None = None):
        self._r: Redis = redis_client or get_redis()
        # Log de debug para confirmar DB
        from redis_config import REDIS_DB
        logger.debug(f"JobRepository initialized with Redis DB {REDIS_DB}")

    # ── Internal: serializa/deserializa campos JSON ───────────
    def _serialize(self, data: Dict[str, Any]) -> Dict[str, str]:
        """Converte campos complexos (list/dict) em JSON string."""
        out: Dict[str, str] = {}
        for k, v in data.items():
            if isinstance(v, (list, dict)):
                out[k] = json.dumps(v, ensure_ascii=False)
            elif v is None:
                out[k] = ""
            else:
                out[k] = str(v)
        return out

    def _deserialize(self, raw: Dict[str, str]) -> Dict[str, Any]:
        """Converte JSON strings de volta para list/dict."""
        JSON_FIELDS = {"findings", "summary", "ports"}
        out: Dict[str, Any] = {}
        for k, v in raw.items():
            if k in JSON_FIELDS and v:
                try:
                    out[k] = json.loads(v)
                except json.JSONDecodeError:
                    out[k] = v
            else:
                out[k] = v if v != "" else None
        return out

    # ── Operações CRUD ────────────────────────────────────────

    @with_retry()
    async def create(self, job_id: str, job_data: Dict[str, Any], organization_id: str) -> bool:
        """
        Cria job no Redis (Hash) dentro do namespace da Org.
        """
        if _circuit.is_open():
            raise RedisError("Circuit breaker aberto — Redis indisponível")

        try:
            key = _job_key(job_id, organization_id)
            # Garante que o organization_id está nos dados
            job_data["organization_id"] = organization_id
            serialized = self._serialize(job_data)

            async with self._r.pipeline(transaction=True) as pipe:
                await pipe.hset(key, mapping=serialized)

                # Índice por Organização
                ts = datetime.now(timezone.utc).timestamp()
                await pipe.zadd(_org_index_key(organization_id), {job_id: ts})

                await pipe.hincrby(STATS_KEY, "queued", 1)
                await pipe.execute()

            _circuit.record_success()
            logger.info("Job criado no Redis (Multi-tenant)", extra={"job_id": job_id, "org": organization_id})
            return True

        except RedisError as exc:
            _circuit.record_failure()
            raise

    @with_retry()
    async def get(self, job_id: str, organization_id: str) -> Optional[Dict[str, Any]]:
        """Busca job no namespace da organização."""
        if _circuit.is_open():
            raise RedisError("Circuit breaker aberto")

        try:
            raw = await self._r.hgetall(_job_key(job_id, organization_id))
            if not raw:
                return None
            _circuit.record_success()
            return self._deserialize(raw)
        except RedisError:
            _circuit.record_failure()
            raise

    @with_retry()
    async def update(self, job_id: str, updates: Dict[str, Any], organization_id: str) -> bool:
        """
        Atualiza campos do job garantindo o namespace da org.
        """
        if _circuit.is_open():
            raise RedisError("Circuit breaker aberto")

        try:
            key = _job_key(job_id, organization_id)
            serialized = self._serialize(updates)

            async with self._r.pipeline(transaction=True) as pipe:
                await pipe.hset(key, mapping=serialized)

                new_status = updates.get("status")
                if new_status in ("completed", "failed"):
                    await pipe.expire(key, JOB_TTL)
                    # Atualiza contadores
                    if new_status == "completed":
                        await pipe.hincrby(STATS_KEY, "completed", 1)
                    else:
                        await pipe.hincrby(STATS_KEY, "failed", 1)

                await pipe.execute()

            _circuit.record_success()
            return True
        except RedisError:
            _circuit.record_failure()
            raise

    @with_retry()
    async def append_finding(self, job_id: str, finding: Dict[str, Any], organization_id: str) -> bool:
        """Adiciona finding no namespace da org."""
        if _circuit.is_open():
            raise RedisError("Circuit breaker aberto")

        key = _job_key(job_id, organization_id)
        try:
            async with self._r.pipeline(transaction=True) as pipe:
                while True:
                    try:
                        await pipe.watch(key)
                        raw_findings = await pipe.hget(key, "findings")
                        current = json.loads(raw_findings) if raw_findings else []
                        current.append(finding)

                        pipe.multi()
                        await pipe.hset(key, "findings", json.dumps(current, ensure_ascii=False))
                        await pipe.execute()
                        break
                    except aioredis.WatchError:
                        continue

            _circuit.record_success()
            return True
        except RedisError:
            _circuit.record_failure()
            raise

    @with_retry()
    async def delete(self, job_id: str, organization_id: str) -> bool:
        """Remove job e remove do índice da org."""
        if _circuit.is_open():
            raise RedisError("Circuit breaker aberto")

        try:
            async with self._r.pipeline(transaction=True) as pipe:
                await pipe.delete(_job_key(job_id, organization_id))
                await pipe.zrem(_org_index_key(organization_id), job_id)
                await pipe.execute()

            _circuit.record_success()
            return True
        except RedisError:
            _circuit.record_failure()
            raise

    @with_retry()
    async def list_by_org(self, organization_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Retorna jobs da org."""
        if _circuit.is_open():
            raise RedisError("Circuit breaker aberto")

        try:
            job_ids = await self._r.zrevrange(_org_index_key(organization_id), 0, limit - 1)
            if not job_ids:
                return []

            async with self._r.pipeline(transaction=False) as pipe:
                for jid in job_ids:
                    await pipe.hgetall(_job_key(jid, organization_id))
                results = await pipe.execute()

            jobs = []
            for raw in results:
                if raw:
                    jobs.append(self._deserialize(raw))

            _circuit.record_success()
            return jobs
        except RedisError:
            _circuit.record_failure()
            raise

    @with_retry()
    async def get_stats(self) -> Dict[str, int]:
        """Retorna contadores de jobs por status."""
        if _circuit.is_open():
            raise RedisError("Circuit breaker aberto")

        try:
            raw = await self._r.hgetall(STATS_KEY)
            stats = {k: int(v) for k, v in raw.items()}
            _circuit.record_success()
            return stats
        except RedisError:
            _circuit.record_failure()
            raise

    async def cleanup_expired(self) -> int:
        """
        Remove entradas de índice (Sorted Set) que apontam para chaves
        expiradas (job hash não existe mais no Redis).
        """
        removed = 0
        try:
            # Varre todos os índices de usuário
            cursor = 0
            while True:
                cursor, keys = await self._r.scan(cursor, match="jobs:org:*", count=100)
                for idx_key in keys:
                    org_id = idx_key.split(":")[-1]
                    job_ids = await self._r.zrange(idx_key, 0, -1)
                    for jid in job_ids:
                        exists = await self._r.exists(_job_key(jid, org_id))
                        if not exists:
                            await self._r.zrem(idx_key, jid)
                            removed += 1
                if cursor == 0:
                    break

            if removed:
                logger.info(f"Cleanup: removidas {removed} entradas de índice obsoletas")
        except RedisError as e:
            logger.error(f"Erro no cleanup de índices Redis: {e}")

        return removed
