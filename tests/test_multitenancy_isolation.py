import asyncio
import uuid
import sys
import os

# Ajuste de path para o container
sys.path.insert(0, "/app")
sys.path.insert(0, "/app/src")

from repository.job_repository import JobRepository

async def test_redis_isolation():
    print("🚀 Iniciando Teste de Isolamento de Cache (Redis) Multi-tenant")
    job_repo = JobRepository()

    # 1. IDs de teste
    org_a = f"org_a_{uuid.uuid4().hex[:4]}"
    org_b = f"org_b_{uuid.uuid4().hex[:4]}"
    job_id = f"job_secret_{uuid.uuid4().hex[:4]}"

    # 2. Org A cria um job
    job_data = {"id": job_id, "target": "http://tenant-a.com", "organization_id": org_a}
    await job_repo.create(job_id, job_data, organization_id=org_a)
    print(f"✅ Job {job_id} persistido para Org A")

    # 3. Org B tenta acessar o Job ID da Org A
    print(f"🔍 Tenant B tentando interceptar Job ID da Org A...")
    job_as_b = await job_repo.get(job_id, organization_id=org_b)
    
    if job_as_b is None:
        print("🛡️  SUCESSO: Isolamento de Namespace confirmado no Redis. Org B não vê dados da Org A.")
    else:
        print("❌ FALHA: Org B conseguiu acessar dados privados da Org A!")
        sys.exit(1)

    # 4. Org A consegue acessar seus próprios dados?
    job_as_a = await job_repo.get(job_id, organization_id=org_a)
    if job_as_a and job_as_a.get("target") == "http://tenant-a.com":
         print("✅ SUCESSO: Org A consegue acessar seus dados normalmente.")
    else:
         print("❌ FALHA: Org A perdeu acesso aos seus próprios dados!")
         sys.exit(1)

    print("\n🏆 Teste de isolamento de cache passou com 100% de sucesso!")

if __name__ == "__main__":
    asyncio.run(test_redis_isolation())
