from sqlalchemy import Column, String, Integer, DateTime, JSON, ForeignKey, Boolean, UniqueConstraint
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .database import Base

class Organization(Base):
    """
    Entidade Raiz de Multi-tenancy.
    Todos os recursos (scans, projects, members) pertencem a uma Organização.
    """
    __tablename__ = "organizations"

    id         = Column(String, primary_key=True, index=True)
    name       = Column(String, nullable=False)
    owner_id   = Column(String, index=True, nullable=False) # Supabase User ID do Criador
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    members = relationship("OrganizationMember", back_populates="organization", cascade="all, delete-orphan")
    scans   = relationship("ScanDB", back_populates="organization", cascade="all, delete-orphan")
    subscription = relationship("Subscription", back_populates="organization", uselist=False, cascade="all, delete-orphan")
    usage   = relationship("PlanUsage", back_populates="organization", uselist=False, cascade="all, delete-orphan")

class OrganizationMember(Base):
    """
    Tabela de junção User <-> Organization com Roles.
    Garante que um usuário possa pertencer a múltiplas orgs.
    """
    __tablename__ = "organization_members"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    organization_id = Column(String, ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=False)
    user_id         = Column(String, index=True, nullable=False) # Supabase User ID
    role            = Column(String, default="member") # admin, member

    organization = relationship("Organization", back_populates="members")

    __table_args__ = (
        UniqueConstraint("user_id", "organization_id", name="uq_user_org"),
    )

class ScanDB(Base):
    """
    Modelo do SQLAlchemy para representar a Tabela `scans` no PostgreSQL.
    Cada scan pertence a um tenant (user_id do Supabase).
    """
    __tablename__ = "scans"
    
    id = Column(String, primary_key=True, index=True)
    organization_id = Column(String, ForeignKey("organizations.id", ondelete="CASCADE"), index=True, nullable=True) # Nullable p/ migração
    user_id = Column(String, index=True, nullable=False)  # Supabase Auth ID (Legacy support)
    target = Column(String, nullable=False)
    status = Column(String, default="pending")
    scan_type = Column(String, default="full")
    options = Column(JSON, nullable=True) # ports, timeout, etc
    
    # Metadados de execução
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error = Column(String, nullable=True)

    organization = relationship("Organization", back_populates="scans")


class FindingDB(Base):
    """
    Representa uma vulnerabilidade encontrada.
    """
    __tablename__ = "findings"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    
    # Detalhes da Vuln
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False) # low, medium, high, critical
    endpoint = Column(String, nullable=True)
    method = Column(String, nullable=True)
    payload = Column(String, nullable=True)
    details = Column(String, nullable=True)
    confidence = Column(Integer, default=100)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Subscription(Base):
    """
    Estado da assinatura Stripe para a Organização.
    """
    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    organization_id = Column(String, ForeignKey("organizations.id", ondelete="CASCADE"), unique=True, index=True)
    stripe_customer_id = Column(String, index=True)
    stripe_subscription_id = Column(String, index=True)
    plan = Column(String, default="free") # free, pro, enterprise
    status = Column(String, default="active") # active, past_due, canceled
    current_period_end = Column(DateTime(timezone=True), nullable=True)

    organization = relationship("Organization", back_populates="subscription")

class PlanUsage(Base):
    """
    Controle de Quotas por Ciclo Billing.
    """
    __tablename__ = "plan_usage"

    id = Column(Integer, primary_key=True, autoincrement=True)
    organization_id = Column(String, ForeignKey("organizations.id", ondelete="CASCADE"), unique=True, index=True)
    scans_count = Column(Integer, default=0) # Quantos scans fez no mês
    reset_at = Column(DateTime(timezone=True)) # Próximo reset de quota

    organization = relationship("Organization", back_populates="usage")
