"""
tests/test_redis_repository.py

Suíte de testes para o JobRepository usando fakeredis (sem precisar de Redis real).
Instale com: pip install fakeredis pytest pytest-asyncio

Execute com:
    pytest tests/test_redis_repository.py -v
"""
import asyncio
import json
import pytest
import fakeredis.aioredis as fakeredis

from repository.job_repository import JobRepository


# ── Fixture: cria repositório com Redis fake ──────────────────
@pytest.fixture
def fake_redis():
    return fakeredis.FakeRedis(decode_responses=True)


@pytest.fixture
def repo(fake_redis):
    return JobRepository(redis_client=fake_redis)


# ── Dados de exemplo ──────────────────────────────────────────
def sample_job(job_id: str = "test-job-1", user_id: str = "user-abc") -> dict:
    return {
        "id":         job_id,
        "target":     "http://example.com",
        "ports":      [80, 443],
        "status":     "queued",
        "user_id":    user_id,
        "created_at": "2026-03-07T00:00:00+00:00",
        "findings":   [],
    }


# ─────────────────────────────────────────────────────────────
# Teste 1: create + get
# ─────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_create_and_get_job(repo):
    """Criar um job e recuperá-lo pelo ID deve retornar os mesmos dados."""
    job = sample_job("job-001")
    await repo.create("job-001", job)

    result = await repo.get("job-001")
    assert result is not None, "Job deve existir após criação"
    assert result["id"] == "job-001"
    assert result["target"] == "http://example.com"
    assert result["status"] == "queued"
    assert isinstance(result["findings"], list)


# ─────────────────────────────────────────────────────────────
# Teste 2: TTL após job finalizar
# ─────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_job_ttl_expiration(repo, fake_redis):
    """
    Ao marcar job como 'completed', o repositório deve aplicar EXPIRE.
    Simulamos TTL de 1s e verificamos que a chave some após expiração.
    """
    import repository.job_repository as repo_module
    original_ttl = repo_module.JOB_TTL

    try:
        repo_module.JOB_TTL = 1  # TTL de 1 segundo para o teste

        await repo.create("job-ttl", sample_job("job-ttl"))
        await repo.update("job-ttl", {"status": "completed"})

        # Deve existir agora
        assert await repo.get("job-ttl") is not None

        # Aguarda expiração
        await asyncio.sleep(1.1)
        result = await repo.get("job-ttl")
        assert result is None, "Job deve ter expirado após TTL"
    finally:
        repo_module.JOB_TTL = original_ttl


# ─────────────────────────────────────────────────────────────
# Teste 3: list_by_user
# ─────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_list_by_user(repo):
    """Criar 3 jobs para o mesmo usuário e listar deve retornar todos."""
    user_id = "user-xyz"
    for i in range(3):
        jid = f"job-{i}"
        await repo.create(jid, sample_job(jid, user_id))

    jobs = await repo.list_by_user(user_id, limit=10)
    assert len(jobs) == 3, f"Esperado 3 jobs, obtido {len(jobs)}"

    ids = {j["id"] for j in jobs}
    assert {"job-0", "job-1", "job-2"} == ids


# ─────────────────────────────────────────────────────────────
# Teste 4: get_stats (contadores)
# ─────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_stats_increment(repo):
    """Criar 2 jobs e completar 1 — stats devem refletir corretamente."""
    await repo.create("job-s1", sample_job("job-s1"))
    await repo.create("job-s2", sample_job("job-s2"))
    await repo.update("job-s1", {"status": "completed"})
    await repo.update("job-s2", {"status": "failed"})

    stats = await repo.get_stats()
    assert stats.get("queued", 0) >= 2, "Deve ter ao menos 2 queued incrementados"
    assert stats.get("completed", 0) >= 1, "Deve ter 1 completed"
    assert stats.get("failed", 0) >= 1, "Deve ter 1 failed"


# ─────────────────────────────────────────────────────────────
# Teste 5: falha de conexão
# ─────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_connection_failure_handling():
    """
    Repositório com Redis em host inválido deve lançar RedisError
    (após retries) e não travar o loop de eventos indefinidamente.
    """
    import redis.asyncio as aioredis
    from redis.exceptions import RedisError

    bad_redis = aioredis.Redis(host="invalid-host-that-does-not-exist", port=9999, socket_connect_timeout=0.1)
    bad_repo = JobRepository(redis_client=bad_redis)

    with pytest.raises(RedisError):
        await bad_repo.get("qualquer-job-id")


# ─────────────────────────────────────────────────────────────
# Teste 6: append_finding (atomicidade)
# ─────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_append_finding_atomic(repo):
    """Adicionar múltiplos findings ao mesmo job deve preservar todos."""
    await repo.create("job-find", sample_job("job-find"))

    findings = [
        {"title": "SQLi Detected",     "severity": "CRITICAL", "endpoint": "/api/users"},
        {"title": "BOLA Vulnerability", "severity": "HIGH",     "endpoint": "/api/orders/1"},
    ]

    for f in findings:
        await repo.append_finding("job-find", f)

    job = await repo.get("job-find")
    assert len(job["findings"]) == 2, "Deve ter 2 findings persistidos"
    assert job["findings"][0]["title"] == "SQLi Detected"
    assert job["findings"][1]["title"] == "BOLA Vulnerability"
