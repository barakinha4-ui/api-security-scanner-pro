"""
Sistema de Planos e Billing para API Security Scanner Pro
"""
from enum import Enum
from typing import Dict, Optional
from pydantic import BaseModel


class Plan(str, Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class PlanFeatures(BaseModel):
    """Features de cada plano"""
    plan: Plan
    name: str
    price_brl: float
    scans_per_month: int
    max_endpoints: int
    concurrent_scans: int
    api_access: bool
    custom_reports: bool
    priority_support: bool
    on_premise: bool
    sla: Optional[str] = None


PLANS: Dict[Plan, PlanFeatures] = {
    Plan.FREE: PlanFeatures(
        plan=Plan.FREE,
        name="Gratuito",
        price_brl=0,
        scans_per_month=5,
        max_endpoints=50,
        concurrent_scans=1,
        api_access=False,
        custom_reports=False,
        priority_support=False,
        on_premise=False,
    ),
    Plan.PRO: PlanFeatures(
        plan=Plan.PRO,
        name="Pro",
        price_brl=197,
        scans_per_month=-1,  # unlimited
        max_endpoints=-1,    # unlimited
        concurrent_scans=5,
        api_access=True,
        custom_reports=True,
        priority_support=True,
        on_premise=False,
    ),
    Plan.ENTERPRISE: PlanFeatures(
        plan=Plan.ENTERPRISE,
        name="Enterprise",
        price_brl=0,  # custom
        scans_per_month=-1,
        max_endpoints=-1,
        concurrent_scans=-1,
        api_access=True,
        custom_reports=True,
        priority_support=True,
        on_premise=True,
        sla="99.9%",
    ),
}


def get_plan_features(plan: Plan) -> PlanFeatures:
    """Retorna as features de um plano"""
    return PLANS.get(plan, PLANS[Plan.FREE])


def can_run_scan(plan: Plan, current_usage: int) -> bool:
    """Verifica se o usuário pode rodar um scan"""
    features = get_plan_features(plan)
    
    if features.scans_per_month == -1:
        return True  # unlimited
    
    return current_usage < features.scans_per_month


def get_remaining_scans(plan: Plan, current_usage: int) -> int:
    """Retorna scans restantes no plano"""
    features = get_plan_features(plan)
    
    if features.scans_per_month == -1:
        return -1  # unlimited
    
    return max(0, features.scans_per_month - current_usage)


# Plan upgrade paths
PLAN_UPGRADES = {
    Plan.FREE: Plan.PRO,
    Plan.PRO: Plan.ENTERPRISE,
}


def get_next_plan(current: Plan) -> Optional[Plan]:
    """Retorna o próximo plano disponível"""
    return PLAN_UPGRADES.get(current)
