import asyncio
import uuid
import sys
import os
from datetime import datetime, timezone

# Ajuste de path para o container/local
sys.path.insert(0, "/app")
sys.path.insert(0, "/app/src")
sys.path.insert(0, r"C:\Users\gusta\Desktop\api\api-security-scanner-pro\src")
sys.path.insert(0, r"C:\Users\gusta\Desktop\api\api-security-scanner-pro")

from apiscanner.core.database import AsyncSessionLocal, init_models
from apiscanner.core.models_db import Organization, Subscription, PlanUsage
from apiscanner.core.billing_logic import check_scan_quota, increment_usage
from fastapi import HTTPException

async def test_quota_enforcement():
    print("🚀 Iniciando Teste de Quotas (Billing) SaaS")
    await init_models()
    
    org_id = f"org_test_{uuid.uuid4().hex[:4]}"
    
    async with AsyncSessionLocal() as db:
        # 1. Setup: Criar Org com Plano Free (Limite 5)
        print(f"📦 Configurando Org {org_id} no plano FREE...")
        db.add(Organization(id=org_id, name="Quota Test Org", owner_id="test_user"))
        db.add(Subscription(organization_id=org_id, plan="free", status="active"))
        db.add(PlanUsage(organization_id=org_id, scans_count=0))
        await db.commit()

        # 2. Simular 5 scans (Limite exato)
        print("⚡ Simulando 5 scans...")
        for i in range(5):
            await check_scan_quota(org_id, db)
            await increment_usage(org_id, db)
            print(f"   Scan {i+1}/5 OK")

        # 3. Tentar o 6º scan (Deve falhar)
        print("⚠️  Tentando o 6º scan (expectativa: 403 Forbidden)...")
        try:
            await check_scan_quota(org_id, db)
            print("❌ FALHA: O sistema permitiu o 6º scan mesmo no plano Free!")
            sys.exit(1)
        except HTTPException as e:
            if e.status_code == 403:
                print(f"🛡️  SUCESSO: Bloqueio 403 confirmado. Mensagem: {e.detail}")
            else:
                print(f"❌ FALHA: Recebeu erro inesperado: {e.status_code}")
                sys.exit(1)

    print("\n🏆 Teste de enforce de quotas passou com 100% de sucesso!")

if __name__ == "__main__":
    asyncio.run(test_quota_enforcement())
