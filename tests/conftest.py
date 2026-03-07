"""
tests/conftest.py — Setup e teardown automático para pytest

Este arquivo é carregado automaticamente pelo pytest.
Define fixtures compartilhadas entre todos os testes.
"""
import os
import sys
import pytest

# Garante que o root do projeto esteja no sys.path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


# ── Fixtures de autenticação ─────────────────────────────────
@pytest.fixture(scope="session")
def api_key():
    """Chave de API para os testes (lida do ambiente)."""
    return os.getenv("API_KEY_SECRET", "super-secret-local-key")


@pytest.fixture(scope="session")
def auth_headers(api_key):
    """Headers de autenticação reutilizáveis em toda a suíte."""
    return {"Authorization": f"Bearer {api_key}"}


@pytest.fixture(scope="session")
def api_base():
    """URL base do servidor (lida do ambiente)."""
    return os.getenv("LOCUST_HOST", "http://localhost:8000")


@pytest.fixture(scope="session")
def test_target():
    """URL do alvo de scan para testes."""
    return os.getenv("TEST_TARGET", "http://localhost:9000")


# ── Fixtures de ciclo de vida de jobs ─────────────────────────
@pytest.fixture
def job_tracker():
    """
    Rastreia jobs criados durante o teste.
    Ao final do teste, faz cleanup automático.
    """
    from tests.fixtures import cleanup_jobs
    jobs: list[str] = []
    yield jobs
    # Teardown: limpa os jobs criados
    if jobs:
        result = cleanup_jobs(jobs)
        print(f"\n[conftest] Cleanup: {result['deleted']} jobs removidos, {result['failed']} falhas")


# ── Fixtures do repositório Redis (para testes unitários) ─────
@pytest.fixture
def fake_redis_client():
    """Instância de FakeRedis para testes unitários sem Redis real."""
    try:
        import fakeredis.aioredis as fakeredis
        return fakeredis.FakeRedis(decode_responses=True)
    except ImportError:
        pytest.skip("fakeredis não instalado — execute: pip install fakeredis")


@pytest.fixture
def job_repo(fake_redis_client):
    """Repositório de jobs usando FakeRedis — isolado por teste."""
    from repository.job_repository import JobRepository
    return JobRepository(redis_client=fake_redis_client)


# ── Configuração de pytest-asyncio ────────────────────────────
def pytest_configure(config):
    """Configura modo assíncrono para todos os testes marcados com @pytest.mark.asyncio."""
    config.addinivalue_line(
        "markers", "asyncio: marca teste como assíncrono (requer pytest-asyncio)"
    )
