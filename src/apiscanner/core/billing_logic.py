import stripe
import os
import logging
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status
from .models_db import Organization, Subscription, PlanUsage

logger = logging.getLogger("billing_logic")

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

# Configuração de Planos
PLAN_LIMITS = {
    "free": 5,
    "pro": 100,
    "enterprise": 999999
}

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

async def check_scan_quota(organization_id: str, db: AsyncSession):
    """
    Verifica se a organização atingiu o limite de scans do plano.
    """
    # 1. Busca plano e uso
    stmt = (
        select(Subscription, PlanUsage)
        .join(PlanUsage, Subscription.organization_id == PlanUsage.organization_id)
        .where(Subscription.organization_id == organization_id)
    )
    result = await db.execute(stmt)
    row = result.first()

    if not row:
        # Se não existe registro, cria um default (Free)
        subscription = Subscription(organization_id=organization_id, plan="free", status="active")
        usage = PlanUsage(organization_id=organization_id, scans_count=0)
        db.add_all([subscription, usage])
        await db.commit()
        plan = "free"
        current_usage = 0
    else:
        subscription, usage = row
        plan = subscription.plan
        current_usage = usage.scans_count

    # 2. Valida quota
    limit = PLAN_LIMITS.get(plan, 5)
    if current_usage >= limit:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Quota excedida para o plano {plan.upper()}. Limite: {limit} scans/mês."
        )
    
    return True

async def increment_usage(organization_id: str, db: AsyncSession):
    """Incrementa o contador de scans da organização."""
    stmt = select(PlanUsage).where(PlanUsage.organization_id == organization_id)
    result = await db.execute(stmt)
    usage = result.scalar_one_or_none()
    
    if usage:
        usage.scans_count += 1
        await db.commit()

async def create_checkout_session(organization_id: str, price_id: str, success_url: str, cancel_url: str):
    """Gera link de checkout do Stripe."""
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{'price': price_id, 'quantity': 1}],
            mode='subscription',
            success_url=success_url,
            cancel_url=cancel_url,
            subscription_data={
                'metadata': {'organization_id': organization_id}
            },
            client_reference_id=organization_id
        )
        return session.url
    except Exception as e:
        logger.error(f"Stripe session error: {e}")
        raise HTTPException(status_code=500, detail="Erro ao criar sessão de pagamento")

async def handle_stripe_webhook(payload: bytes, sig_header: str, db: AsyncSession):
    """Processa eventos do Stripe (Assinatura paga, cancelada, etc)."""
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except Exception as e:
        logger.error(f"Stripe Webhook signature error: {e}")
        return False

    data = event['data']['object']
    event_type = event['type']

    if event_type == "checkout.session.completed":
        org_id = data.get("client_reference_id")
        sub_id = data.get("subscription")
        cust_id = data.get("customer")
        
        # Ativa o plano
        stmt = select(Subscription).where(Subscription.organization_id == org_id)
        result = await db.execute(stmt)
        subscription = result.scalar_one_or_none()
        
        if subscription:
            subscription.stripe_subscription_id = sub_id
            subscription.stripe_customer_id = cust_id
            subscription.status = "active"
            # TODO: Mapear price_id para o nome do plano (pro/enterprise)
            subscription.plan = "pro" 
            await db.commit()

    elif event_type == "customer.subscription.deleted":
        sub_id = data.get("id")
        stmt = select(Subscription).where(Subscription.stripe_subscription_id == sub_id)
        result = await db.execute(stmt)
        subscription = result.scalar_one_or_none()
        if subscription:
            subscription.status = "canceled"
            subscription.plan = "free"
            await db.commit()

    return True
