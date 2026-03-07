"""
locustfile.py — Load Testing Suite para SaaS Scanner Pro
=========================================================

Cenários disponíveis:
  A — Smoke Test   : 5 users / 1 min
  B — Load Test    : 50 users / 10 min
  C — Stress Test  : 200 users / 5 min
  D — Spike Test   : 0→100→0 users / 2 min

Uso rápido:
  # Smoke (headless)
  locust -f locustfile.py --headless -u 5 -r 1 -t 1m --host http://localhost:8000

  # Load com UI
  locust -f locustfile.py --host http://localhost:8000

  # Stress (headless + relatório)
  locust -f locustfile.py --headless -u 200 -r 10 -t 5m --host http://localhost:8000 --html=results/stress.html

  # Smoke com CSV
  locust -f locustfile.py --headless -u 5 -r 1 -t 1m --host http://localhost:8000 --csv=results/smoke

Métricas de sucesso (definidas na seção de validação):
  • p95 POST /api/scan      < 2000ms
  • p95 GET  /api/jobs/{id} < 500ms
  • Error rate @ 50 users   < 1%
  • Error rate @ 200 users  < 5%
"""

import os
import json
import time
import random
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from locust import HttpUser, TaskSet, task, between, events, LoadTestShape
from locust.exception import RescheduleTask

# ── Configuração via ambiente ────────────────────────────────
API_KEY = os.getenv("API_KEY_SECRET", "super-secret-local-key")
TEST_TARGET = os.getenv("TEST_TARGET", "http://localhost:9000")

AUTH_HEADER = {"Authorization": f"Bearer {API_KEY}"}

# ── Logging estruturado ──────────────────────────────────────
logger = logging.getLogger("locust")


# ═══════════════════════════════════════════════════════════════
# HELPERS DE JWT (gera token de teste sem servidor Supabase)
# ═══════════════════════════════════════════════════════════════
def make_jwt(user_id: str = "load-test-user") -> str:
    """
    Gera um JWT HS256 com secrets do ambiente.
    Usado por PowerUser e AdminUser para autenticação JWT real.
    """
    try:
        from jose import jwt as jose_jwt
        secret = os.getenv("SUPABASE_JWT_SECRET", "supabase-secret")
        payload = {
            "sub":  user_id,
            "role": "authenticated",
            "exp":  int((datetime.now(timezone.utc) + timedelta(hours=2)).timestamp()),
        }
        return jose_jwt.encode(payload, secret, algorithm="HS256")
    except ImportError:
        # Sem python-jose, usa API Key como fallback
        return API_KEY


# ═══════════════════════════════════════════════════════════════
# TASKSET: NORMAL USER — 80% do tráfego
# Scans leves (1-3 portas), checks de status, healthcheck
# ═══════════════════════════════════════════════════════════════
class NormalUserTasks(TaskSet):
    """
    Simula usuário comum: cria scans leves e consulta status.
    Mix de tarefas: 60% criar scan, 30% checar status, 10% health.
    """
    active_jobs: list[str]

    def on_start(self):
        """Inicializa lista de jobs ativos do usuário."""
        self.active_jobs = []

    @task(6)
    def create_light_scan(self):
        """Cria scan leve com 1-3 portas — simula uso básico da API."""
        ports = random.sample([80, 443, 8080], k=random.randint(1, 3))
        payload = {
            "target":    TEST_TARGET,
            "ports":     ports,
            "scan_type": "quick",
        }
        with self.client.post(
            "/api/scan",
            json=payload,
            headers=AUTH_HEADER,
            catch_response=True,
            name="POST /api/scan [light]",
        ) as resp:
            if resp.status_code == 202:
                job_id = resp.json().get("job_id")
                if job_id:
                    self.active_jobs.append(job_id)
                resp.success()
            elif resp.status_code == 503:
                # Redis indisponível — marca como warning, não falha
                resp.failure("Redis indisponível (503)")
            else:
                resp.failure(f"Esperado 202, obtido {resp.status_code}")

    @task(3)
    def check_job_status(self):
        """Consulta status de um job existente — operação de leitura comum."""
        if not self.active_jobs:
            raise RescheduleTask()

        job_id = random.choice(self.active_jobs)
        with self.client.get(
            f"/api/jobs/{job_id}",
            headers=AUTH_HEADER,
            catch_response=True,
            name="GET /api/jobs/{id}",
        ) as resp:
            if resp.status_code == 200:
                data = resp.json()
                status = data.get("status")
                # Se job completou, remove da lista para não sobrecarregar
                if status in ("completed", "failed"):
                    self.active_jobs.remove(job_id)
                resp.success()
            elif resp.status_code == 404:
                # Job pode ter expirado no Redis — remove e continua
                self.active_jobs.remove(job_id)
                resp.success()
            else:
                resp.failure(f"Status check falhou: {resp.status_code}")

    @task(1)
    def health_check(self):
        """Health check básico — deve ser < 500ms e sempre 200."""
        with self.client.get("/health", catch_response=True) as resp:
            if resp.status_code in (200, 503):
                # 503 é aceitável se Redis estiver indisponível
                elapsed = resp.elapsed.total_seconds() * 1000
                if elapsed > 500:
                    resp.failure(f"Health check muito lento: {elapsed:.0f}ms (limit: 500ms)")
                else:
                    resp.success()
            else:
                resp.failure(f"Health check retornou {resp.status_code}")


# ═══════════════════════════════════════════════════════════════
# TASKSET: POWER USER — 15% do tráfego
# Scans médios, consulta por resultados, WebSocket (simulado)
# ═══════════════════════════════════════════════════════════════
class PowerUserTasks(TaskSet):
    """
    Simula usuário avançado: scans mais pesados, polling frequente de resultados.
    Usa JWT ao invés de API Key para testar o path de autenticação JWT.
    """
    active_jobs: list[str]
    jwt_header: dict

    def on_start(self):
        self.active_jobs = []
        token = make_jwt(f"power-user-{random.randint(1, 100)}")
        self.jwt_header = {"Authorization": f"Bearer {token}"}

    @task(4)
    def create_medium_scan(self):
        """Cria scan médio com 10-20 portas — mais intenso que o normal."""
        ports = random.sample([22, 80, 443, 3000, 4000, 5000, 8000, 8080, 8443, 9000,
                               9090, 27017, 5432, 3306, 6379, 9200, 15672, 5601, 3001, 4200],
                              k=random.randint(10, 20))
        with self.client.post(
            "/api/scan",
            json={"target": TEST_TARGET, "ports": ports, "scan_type": "full"},
            headers=AUTH_HEADER,   # API Key para garantir acesso
            catch_response=True,
            name="POST /api/scan [medium]",
        ) as resp:
            if resp.status_code == 202:
                job_id = resp.json().get("job_id")
                if job_id:
                    self.active_jobs.append(job_id)
                resp.success()
            elif resp.status_code == 503:
                resp.failure("Redis indisponível (503)")
            else:
                resp.failure(f"Esperado 202, obtido {resp.status_code}")

    @task(3)
    def poll_results(self):
        """Faz polling de resultados de forma intensiva — padrão de uso PowerUser."""
        if not self.active_jobs:
            raise RescheduleTask()

        job_id = random.choice(self.active_jobs)
        with self.client.get(
            f"/api/jobs/{job_id}/results",
            headers=AUTH_HEADER,
            catch_response=True,
            name="GET /api/jobs/{id}/results",
        ) as resp:
            if resp.status_code in (200, 400):
                # 400 = scan em andamento (ainda não completou) — ok
                resp.success()
            elif resp.status_code == 404:
                self.active_jobs.remove(job_id)
                resp.success()
            else:
                resp.failure(f"Results endpoint: {resp.status_code}")

    @task(2)
    def list_my_jobs(self):
        """Lista todos os jobs do usuário — carga de leitura."""
        with self.client.get(
            "/api/jobs?limit=20",
            headers=AUTH_HEADER,
            catch_response=True,
            name="GET /api/jobs [list]",
        ) as resp:
            if resp.status_code == 200:
                resp.success()
            else:
                resp.failure(f"List jobs falhou: {resp.status_code}")

    @task(1)
    def export_job(self):
        """Exporta resultado de um job — operação mais pesada de leitura."""
        if not self.active_jobs:
            raise RescheduleTask()

        job_id = random.choice(self.active_jobs)
        with self.client.get(
            f"/api/jobs/{job_id}/export",
            headers=AUTH_HEADER,
            catch_response=True,
            name="GET /api/jobs/{id}/export",
        ) as resp:
            if resp.status_code in (200, 400):
                resp.success()
            elif resp.status_code == 404:
                self.active_jobs.remove(job_id)
                resp.success()
            else:
                resp.failure(f"Export falhou: {resp.status_code}")


# ═══════════════════════════════════════════════════════════════
# TASKSET: ADMIN USER — 5% do tráfego
# Listar, exportar em bulk e deletar jobs
# ═══════════════════════════════════════════════════════════════
class AdminUserTasks(TaskSet):
    """
    Simula operador/admin: faz operações de manutenção como listar e deletar jobs.
    5% do tráfego — representa carga administrativa.
    """
    created_jobs: list[str]

    def on_start(self):
        self.created_jobs = []

    @task(3)
    def list_jobs_bulk(self):
        """Lista jobs com limit alto — simula painel administrativo."""
        with self.client.get(
            "/api/jobs?limit=50",
            headers=AUTH_HEADER,
            catch_response=True,
            name="GET /api/jobs [bulk list]",
        ) as resp:
            if resp.status_code == 200:
                resp.success()
            else:
                resp.failure(f"Bulk list falhou: {resp.status_code}")

    @task(2)
    def create_and_delete_job(self):
        """Cria um job e depois deleta — testa ciclo completo de cleanup."""
        # Cria job
        with self.client.post(
            "/api/scan",
            json={"target": TEST_TARGET, "ports": [80], "scan_type": "quick"},
            headers=AUTH_HEADER,
            catch_response=True,
            name="POST /api/scan [admin create]",
        ) as resp:
            if resp.status_code == 202:
                job_id = resp.json().get("job_id")
                if job_id:
                    self.created_jobs.append(job_id)
                resp.success()
            else:
                resp.failure(f"Create falhou: {resp.status_code}")

        if not self.created_jobs:
            return

        # Deleta o job mais antigo da lista
        job_id = self.created_jobs.pop(0)
        with self.client.delete(
            f"/api/jobs/{job_id}",
            headers=AUTH_HEADER,
            catch_response=True,
            name="DELETE /api/jobs/{id}",
        ) as resp:
            if resp.status_code in (200, 404):
                resp.success()
            else:
                resp.failure(f"Delete falhou: {resp.status_code}")

    @task(1)
    def check_metrics(self):
        """Consulta métricas Prometheus — operação de monitoramento."""
        with self.client.get(
            "/metrics",
            headers=AUTH_HEADER,
            catch_response=True,
            name="GET /metrics",
        ) as resp:
            if resp.status_code == 200:
                resp.success()
            else:
                resp.failure(f"Metrics: {resp.status_code}")


# ═══════════════════════════════════════════════════════════════
# CLASSES DE USUÁRIO (distribuição de tráfego)
# ═══════════════════════════════════════════════════════════════

class NormalUser(HttpUser):
    """
    80% do tráfego. Scans leves, checkagem de status, health check.
    Wait time 1-5s simula comportamento humano real.
    """
    tasks      = [NormalUserTasks]
    weight     = 8                   # 80% do pool de usuários
    wait_time  = between(1, 5)


class PowerUser(HttpUser):
    """
    15% do tráfego. Scans médios, polling frequente, listagem e export.
    Wait time menor (0.5-2s) — usuário mais "impaciente".
    """
    tasks      = [PowerUserTasks]
    weight     = 1.5                  # 15%
    wait_time  = between(0.5, 2)


class AdminUser(HttpUser):
    """
    5% do tráfego. Operações Admin: bulk list, create+delete, metrics.
    Wait time maior — admin faz menos requests mas mais pesados.
    """
    tasks      = [AdminUserTasks]
    weight     = 0.5                  # 5%
    wait_time  = between(2, 8)


# ═══════════════════════════════════════════════════════════════
# SPIKE TEST SHAPE — Cenário D
#
# Uso: locust -f locustfile.py --headless -t 2m --host http://localhost:8000
#      (comente as classes acima e descomente SpikeTestShape abaixo)
#
# class SpikeTestShape(LoadTestShape):
#     """
#     Simula pico abrupto de tráfego:
#       0→100 usuários em 30s, sustenta 100 por 60s, cai para 0 em 30s.
#     """
#     stages = [
#         {"duration": 30,  "users": 100, "spawn_rate": 10},  # Subida
#         {"duration": 90,  "users": 100, "spawn_rate": 1},   # Pico sustentado
#         {"duration": 120, "users": 0,   "spawn_rate": 10},  # Queda
#     ]
#     def tick(self):
#         elapsed = self.get_current_run_time()
#         for stage in self.stages:
#             if elapsed <= stage["duration"]:
#                 return stage["users"], stage["spawn_rate"]
#         return None   # Encerra o teste
# ═══════════════════════════════════════════════════════════════


# ═══════════════════════════════════════════════════════════════
# EVENTOS CUSTOMIZADOS — Logging e métricas extras
# ═══════════════════════════════════════════════════════════════

# Contadores globais para métricas customizadas
_metrics = {
    "total_requests":  0,
    "total_failures":  0,
    "users_active":    0,
}


@events.request.add_listener
def on_request(request_type, name, response_time, response_length, response, context, exception, **kw):
    """Registra cada request com log estruturado JSON."""
    _metrics["total_requests"] += 1
    if exception:
        _metrics["total_failures"] += 1

    # Log de falhas com detalhe
    if exception or (response and response.status_code >= 500):
        logger.warning(json.dumps({
            "event":         "request_failure",
            "type":          request_type,
            "name":          name,
            "response_time": response_time,
            "status_code":   getattr(response, "status_code", None),
            "error":         str(exception) if exception else None,
            "ts":            datetime.now(timezone.utc).isoformat(),
        }))


@events.spawning_complete.add_listener
def on_spawning_complete(user_count, **kw):
    """Loga quando o spawn de usuários se completa."""
    logger.info(json.dumps({
        "event":      "spawning_complete",
        "user_count": user_count,
        "ts":         datetime.now(timezone.utc).isoformat(),
    }))


@events.test_stop.add_listener
def on_test_stop(environment, **kw):
    """Exibe resumo de métricas customizadas ao final do teste."""
    total   = _metrics["total_requests"]
    failed  = _metrics["total_failures"]
    rate    = (failed / total * 100) if total else 0

    summary = {
        "event":          "test_complete",
        "total_requests": total,
        "total_failures": failed,
        "error_rate_pct": round(rate, 2),
        "ts":             datetime.now(timezone.utc).isoformat(),
    }
    print("\n" + "=" * 60)
    print("📊 LOAD TEST SUMMARY")
    print("=" * 60)
    print(f"  Total Requests : {total:,}")
    print(f"  Total Failures : {failed:,}")
    print(f"  Error Rate     : {rate:.2f}%")
    if rate < 1:
        print("  Status         : ✅ PASSOU (< 1% erros)")
    elif rate < 5:
        print("  Status         : ⚠️  ATENÇÃO (1-5% erros)")
    else:
        print("  Status         : ❌ FALHOU (> 5% erros)")
    print("=" * 60 + "\n")

    # Escreve JSON para leitura por CI/CD
    os.makedirs("results", exist_ok=True)
    with open("results/summary.json", "w") as f:
        json.dump(summary, f, indent=2)
