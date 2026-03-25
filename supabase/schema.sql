-- ================================================================
-- API Security Scanner Pro — Supabase Database Schema
-- ================================================================

-- Extensiones
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ================================================================
-- Tabela: Organizations (Multi-tenant)
-- ================================================================
CREATE TABLE public.organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    plan TEXT NOT NULL DEFAULT 'free' CHECK (plan IN ('free', 'pro', 'enterprise')),
    scan_quota INTEGER NOT NULL DEFAULT 100,
    scans_used INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ================================================================
-- Tabela: Users (vinculado ao Supabase Auth)
-- ================================================================
CREATE TABLE public.users (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES public.organizations(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    full_name TEXT,
    role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    avatar_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(id, organization_id)
);

-- ================================================================
-- Tabela: Scans
-- ================================================================
CREATE TABLE public.scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES public.organizations(id) ON DELETE CASCADE NOT NULL,
    user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    target_url TEXT NOT NULL,
    scan_type TEXT NOT NULL DEFAULT 'full' CHECK (scan_type IN ('quick', 'full', 'inject', 'api', 'auth', 'stealth')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    findings_count INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    confidence_score DECIMAL(3,2) DEFAULT 0.00,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_seconds INTEGER,
    report_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ================================================================
-- Tabela: Findings
-- ================================================================
CREATE TABLE public.findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES public.scans(id) ON DELETE CASCADE NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    category TEXT NOT NULL,
    cvss_score DECIMAL(3,1),
    cvss_vector TEXT,
    endpoint TEXT,
    method TEXT,
    parameter TEXT,
    evidence JSONB,
    request_snippet TEXT,
    response_snippet TEXT,
    remediation TEXT,
    confidence DECIMAL(3,2) DEFAULT 0.50,
    false_positive BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ================================================================
-- Tabela: API Keys
-- ================================================================
CREATE TABLE public.api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES public.organizations(id) ON DELETE CASCADE NOT NULL,
    user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    prefix TEXT NOT NULL,
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(organization_id, key_hash)
);

-- ================================================================
-- Tabela: Webhooks
-- ================================================================
CREATE TABLE public.webhooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES public.organizations(id) ON DELETE CASCADE NOT NULL,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    events TEXT[] NOT NULL,
    secret TEXT NOT NULL,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ================================================================
-- Índices para performance
-- ================================================================
CREATE INDEX idx_scans_org ON public.scans(organization_id);
CREATE INDEX idx_scans_status ON public.scans(status);
CREATE INDEX idx_scans_created ON public.scans(created_at DESC);
CREATE INDEX idx_findings_scan ON public.findings(scan_id);
CREATE INDEX idx_findings_severity ON public.findings(severity);
CREATE INDEX idx_users_org ON public.users(organization_id);

-- ================================================================
-- Row Level Security (RLS)
-- ================================================================
ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.webhooks ENABLE ROW LEVEL SECURITY;

-- Políticas de acesso (apenas para SELECT)
-- As operações de INSERT/UPDATE são controladas pela API
CREATE POLICY "organizations_select" ON public.organizations
    FOR SELECT USING (true);

CREATE POLICY "users_select" ON public.users
    FOR SELECT USING (auth.uid() = id);

CREATE POLICY "scans_select" ON public.scans
    FOR SELECT USING (
        organization_id IN (
            SELECT organization_id FROM public.users WHERE id = auth.uid()
        )
    );

CREATE POLICY "findings_select" ON public.findings
    FOR SELECT USING (
        scan_id IN (
            SELECT id FROM public.scans WHERE organization_id IN (
                SELECT organization_id FROM public.users WHERE id = auth.uid()
            )
        )
    );

CREATE POLICY "api_keys_select" ON public.api_keys
    FOR SELECT USING (
        organization_id IN (
            SELECT organization_id FROM public.users WHERE id = auth.uid()
        )
    );

CREATE POLICY "webhooks_select" ON public.webhooks
    FOR SELECT USING (
        organization_id IN (
            SELECT organization_id FROM public.users WHERE id = auth.uid()
        )
    );

-- ================================================================
-- Funções úteis
-- ================================================================
CREATE OR REPLACE FUNCTION public.get_user_organization()
RETURNS TABLE (organization_id UUID, organization_name TEXT, role TEXT)
LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    RETURN QUERY
    SELECT u.organization_id, o.name, u.role
    FROM public.users u
    JOIN public.organizations o ON o.id = u.organization_id
    WHERE u.id = auth.uid();
END;
$$;

CREATE OR REPLACE FUNCTION public.increment_scan_usage(org_id UUID)
RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
    UPDATE public.organizations 
    SET scans_used = scans_used + 1, updated_at = NOW()
    WHERE id = org_id;
END;
$$;

CREATE OR REPLACE FUNCTION public.check_scan_quota(org_id UUID)
RETURNS BOOLEAN LANGUAGE plpgsql AS $$
DECLARE
    quota INTEGER;
    used INTEGER;
BEGIN
    SELECT scan_quota, scans_used INTO quota, used 
    FROM public.organizations WHERE id = org_id;
    RETURN used < quota;
END;
$$;

-- ================================================================
-- Trigger: Auto-criar organização quando usuário se registrar
-- ================================================================
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
DECLARE
    org_id UUID;
BEGIN
    -- Criar organização para o novo usuário
    INSERT INTO public.organizations (name, slug)
    VALUES (NEW.email::text, lower(replace(NEW.email::text, '@', '_')))
    RETURNING id INTO org_id;
    
    -- Adicionar usuário à organização como owner
    INSERT INTO public.users (id, organization_id, email, full_name, role)
    VALUES (NEW.id, org_id, NEW.email, NEW.raw_user_meta_data->>'full_name', 'owner');
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ================================================================
-- Dados de exemplo
-- ================================================================
INSERT INTO public.organizations (name, slug, plan, scan_quota)
VALUES ('Demo Organization', 'demo-org', 'free', 100)
ON CONFLICT (slug) DO NOTHING;
