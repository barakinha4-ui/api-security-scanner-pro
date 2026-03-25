import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from celery.utils.log import get_task_logger

# Adiciona o src/apiscanner ao path para importar o scanner engine
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_PATH = os.path.join(BASE_DIR, "src", "apiscanner")
if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)

from repository.job_repository import JobRepository
from redis_config import get_redis

logger = get_task_logger(__name__)


def _ws_channel(job_id: str) -> str:
    return f"ws:job:{job_id}"


async def _publish_event(job_id: str, payload: dict) -> None:
    """Publica evento no Redis Pub/Sub para o WebSocket."""
    try:
        r = get_redis()
        await r.publish(_ws_channel(job_id), json.dumps(payload, ensure_ascii=False))
        logger.debug(f"Published: {payload.get('type')} -> {_ws_channel(job_id)}")
    except Exception as e:
        logger.warning(f"WS Publish failed for job {job_id}: {e}")


async def _run_scan_logic(self_task, target: str, user_id: str, job_id: str, scan_type: str = "full", ports: list = None, organization_id: str = "default-org-legacy", headers: dict = None):
    """
    Lógica principal do scan com isolamento Multi-tenant.
    """
    logger.info(f"Task {self_task.request.id} started: job={job_id} org={organization_id}")
    job_repo = JobRepository()

    try:
        # 1. Atualiza status para 'running' e notifica o WebSocket
        await job_repo.update(job_id, {
            "status": "running",
            "started_at": datetime.now(timezone.utc).isoformat()
        }, organization_id=organization_id)
        await _publish_event(job_id, {
            "type": "log",
            "status": "running",
            "message": f"🚀 Scan iniciado em {target}",
            "job_id": job_id
        })

        summary = {}
        findings_count = 0

        # 2. Tenta importar e executar o scanner engine
        try:
            import sys
            import os
            # Adiciona 'src' ao path para que 'apiscanner' seja um pacote válido
            src_path = os.path.join(os.getcwd(), "src")
            if src_path not in sys.path:
                sys.path.insert(0, src_path)

            from apiscanner.core.engine import AsyncEngine
            from apiscanner.core.models import ScanResult, Finding
            from apiscanner.scanner import Scanner

            async def on_finding_callback(finding):
                finding_dict = finding.to_dict() if hasattr(finding, "to_dict") else vars(finding)
                finding_dict = {k: str(v) for k, v in finding_dict.items()}
                # Isolamento no Redis
                await job_repo.append_finding(job_id, finding_dict, organization_id=organization_id)
                await _publish_event(job_id, {
                    "type": "finding",
                    "job_id": job_id,
                    "data": finding_dict,
                })

            async def on_log_callback(msg: str):
                await _publish_event(job_id, {
                    "job_id": job_id,
                    "type": "log",
                    "message": str(msg),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })

            async with AsyncEngine(concurrency=20, timeout=300, headers=headers) as engine:
                scanner = Scanner(
                    target=target,
                    engine=engine,
                    scan_type=scan_type,
                    on_finding=on_finding_callback,
                    on_log=on_log_callback
                )
                result = await scanner.run()

            summary = result.summary if hasattr(result, 'summary') else {}
            findings_count = len(result.findings) if hasattr(result, 'findings') else 0

        except ImportError as ie:
            logger.warning(f"Scanner engine import failed: {ie}. Usando fallback.")
            summary = {"error": str(ie)}
            await _publish_event(job_id, {
                "type": "log",
                "message": f"⚠️ Scanner engine indisponível: {ie}",
                "job_id": job_id
            })

        # 3. Finalização — salva tudo no Redis
        await job_repo.update(job_id, {
            "status": "completed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "summary": summary
        }, organization_id=organization_id)
        await _publish_event(job_id, {
            "status": "completed",
            "type": "status",
            "job_id": job_id,
            "summary": summary,
            "message": f"✅ Scan finalizado — {findings_count} vulnerabilidades encontradas"
        })

        return summary

    except Exception as e:
        logger.error(f"Task {self_task.request.id} failed: {e}", exc_info=True)
        try:
            await job_repo.update(job_id, {"status": "failed", "error": str(e)}, organization_id=organization_id)
            await _publish_event(job_id, {
                "status": "failed",
                "type": "status",
                "job_id": job_id,
                "error": str(e),
                "message": f"❌ Scan falhou: {e}"
            })
        except Exception:
            pass
        raise


from celery import current_app as celery


@celery.task(name='scanner.scan_api', bind=True)
def run_api_scan(self, target: str, user_id: str, job_id: str, scan_type: str = "full", ports: list = None, organization_id: str = "default-org-legacy", headers: dict = None):
    """Task Celery que dispara o scan assíncrono usando um event loop dedicado."""
    # asyncio.run() pode conflitar com loops residuais do Celery.
    # Criamos um loop completamente novo para evitar o erro "Event loop is closed".
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_run_scan_logic(self, target, user_id, job_id, scan_type, ports, organization_id, headers))
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception:
            pass
        loop.close()
