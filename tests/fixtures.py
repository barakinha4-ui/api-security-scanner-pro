"""
tests/fixtures.py — Helpers reutilizáveis para testes de carga e unitários

Uso:
    from tests.fixtures import valid_api_key_header, valid_jwt_header, test_target, cleanup_jobs
"""
import os
from datetime import datetime, timezone, timedelta

import requests


# ── Autenticação ─────────────────────────────────────────────
def api_key() -> str:
    """Retorna a API Key configurada no ambiente."""
    return os.getenv("API_KEY_SECRET", "super-secret-local-key")


def valid_api_key_header() -> dict:
    """Header de autenticação via API Key."""
    return {"Authorization": f"Bearer {api_key()}"}


def valid_jwt_header(user_id: str = "test-user") -> dict:
    """Gera header de autenticação via JWT HS256 assinado com SUPABASE_JWT_SECRET."""
    try:
        from jose import jwt
        secret = os.getenv("SUPABASE_JWT_SECRET", "supabase-secret")
        payload = {
            "sub":  user_id,
            "role": "authenticated",
            "exp":  int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        }
        token = jwt.encode(payload, secret, algorithm="HS256")
        return {"Authorization": f"Bearer {token}"}
    except ImportError:
        return valid_api_key_header()


# ── Alvo de teste ─────────────────────────────────────────────
def test_target() -> str:
    """
    Retorna URL alvo para testes.
    Prioriza TEST_TARGET do ambiente (ex: mock server local).
    Fallback: httpbin.org (seguro, público).
    """
    return os.getenv("TEST_TARGET", "http://localhost:9000")


def api_base() -> str:
    """Base URL da API do Scanner."""
    return os.getenv("LOCUST_HOST", "http://localhost:8000")


# ── Ciclo de vida de jobs ─────────────────────────────────────
def create_scan_job(
    target: str | None = None,
    ports: list[int] | None = None,
    scan_type: str = "quick",
    base_url: str | None = None,
) -> str | None:
    """
    Cria um job de scan via API REST e retorna o job_id.
    Retorna None se falhar.
    """
    url = (base_url or api_base()) + "/api/scan"
    payload = {
        "target":    target or test_target(),
        "ports":     ports or [80, 443],
        "scan_type": scan_type,
    }
    try:
        resp = requests.post(url, json=payload, headers=valid_api_key_header(), timeout=10)
        if resp.status_code == 202:
            return resp.json().get("job_id")
    except requests.RequestException:
        pass
    return None


def cleanup_jobs(job_ids: list[str], base_url: str | None = None) -> dict:
    """
    Remove uma lista de jobs via DELETE /api/jobs/{id}.
    Retorna dict com contagem de sucessos e falhas.

    Uso em teardown:
        cleanup_jobs(["job-uuid-1", "job-uuid-2"])
    """
    deleted = 0
    failed  = 0
    url_base = (base_url or api_base()) + "/api/jobs"
    headers  = valid_api_key_header()

    for job_id in job_ids:
        try:
            resp = requests.delete(f"{url_base}/{job_id}", headers=headers, timeout=5)
            if resp.status_code in (200, 404):
                deleted += 1
            else:
                failed += 1
        except requests.RequestException:
            failed += 1

    return {"deleted": deleted, "failed": failed}


def wait_for_job(
    job_id: str,
    timeout_s: int = 120,
    poll_interval: float = 2.0,
    base_url: str | None = None,
) -> dict | None:
    """
    Aguarda um job terminar (polling REST).
    Retorna o dict do job quando status = completed/failed.
    Retorna None se timeout excedido.
    """
    import time
    url     = (base_url or api_base()) + f"/api/jobs/{job_id}"
    headers = valid_api_key_header()
    deadline = time.monotonic() + timeout_s

    while time.monotonic() < deadline:
        try:
            resp = requests.get(url, headers=headers, timeout=5)
            if resp.status_code == 200:
                job = resp.json()
                if job.get("status") in ("completed", "failed"):
                    return job
        except requests.RequestException:
            pass
        time.sleep(poll_interval)

    return None
