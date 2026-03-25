# Deploy no Railway — Guia Rápido

## 1. Configurar Serviços no Railway

### Adicionar Redis
1. No Railway Dashboard → seu projeto
2. Clique "New" → "Database" → "Redis"
3. Copie a URL gerada (ex: `redis://default:xxx@xxx.railway.internal:6379`)

### Adicionar PostgreSQL (opcional, já usa Supabase)
Se quiser migrar do Supabase para Railway PostgreSQL:
1. "New" → "Database" → "PostgreSQL"
2. Copie a DATABASE_URL gerada

---

## 2. Configurar Variáveis de Ambiente

No Railway → Settings → Variables, adicione:

```bash
# ─── Server ─────────────────────────────────
SCANNER_HOST=0.0.0.0
SCANNER_PORT=8000

# ─── Auth ────────────────────────────────────
SCANNER_API_KEY=pWEKniIR-NH1J44myr8hUfxQBPWJsyR6zs3YU5GkG9s
API_KEY_SECRET=QOMA2wWKb7XxsjkJKzrUdNdJb3Z5L_SaaAbhcoZq8KE
SCANNER_ENCRYPTION_KEY=tev5MeqFLbemSjCe4Oxpdm8R3zMRtRLq

# ─── Supabase ───────────────────────────────
SUPABASE_URL=https://hezsyyullrcaywyboexs.supabase.co
SUPABASE_KEY=sua-chave-aqui
SUPABASE_JWT_SECRET=seu-secret-aqui
DATABASE_URL=sua-url-postgres-aqui

# ─── Redis (pegue do Railway) ───────────────
REDIS_URL=redis://default:xxx@xxx.railway.internal:6379
CELERY_BROKER_URL=redis://default:xxx@xxx.railway.internal:6379/0
CELERY_RESULT_BACKEND=redis://default:xxx@xxx.railway.internal:6379/1

# ─── Scanner ────────────────────────────────
MAX_CONCURRENCY=20
REQUEST_TIMEOUT=10

# ─── Security ───────────────────────────────
ALLOW_PRIVATE_TARGETS=false
ALLOWED_ORIGINS=https://seu-app.railway.app,https://vulnexusai.com
```

---

## 3. Fazer Deploy

```bash
# Se você já tem o Railway CLI:
cd C:\Users\gusta\Desktop\api-security\api-security-scanner-pro
railway login
railway link
railway up
```

Ou faça deploy pelo GitHub:
1. Push do código para GitHub
2. No Railway → "New" → "GitHub Repo"
3. Selecione o repositório

---

## 4. Verificar Deploy

Após o deploy, teste:
```bash
# Health check
curl https://seu-app.railway.app/health

# Swagger docs
curl https://seu-app.railway.app/docs

# Login
curl -X POST https://seu-app.railway.app/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "seu@email.com", "password": "sua-senha"}'
```

---

## 5. Configurar Domínio Personalizado (Opcional)

No Railway → Settings → Domains:
1. Clique "Generate Domain" ou "Custom Domain"
2. Adicione seu domínio (ex: `api.vulnexusai.com`)
3. Configure DNS conforme instruções do Railway
