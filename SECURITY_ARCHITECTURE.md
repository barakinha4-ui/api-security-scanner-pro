# SECURITY ARCHITECTURE - API Security Scanner Pro

## 1. Visão Geral de Segurança

Este documento define a arquitetura de segurança do projeto API Security Scanner Pro, estabelecendo padrões e implementações para proteção contra vulnerabilidades identificadas.

## 2. Camadas de Segurança

```
┌─────────────────────────────────────────────────────────────┐
│                    SEGURANÇA EXTERNA                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐│
│  │   WAF       │  │   Rate      │  │  IP Allowlist      ││
│  │   Layer     │  │   Limiting  │  │  (SSRF Protection) ││
│  └─────────────┘  └─────────────┘  └─────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                    AUTENTICAÇÃO                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐│
│  │   JWT       │  │   API Key   │  │  Supabase Auth      ││
│  │   Validate  │  │   Compare   │  │  (OAuth2/OIDC)      ││
│  └─────────────┘  └─────────────┘  └─────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                    AUTORIZAÇÃO                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐│
│  │   RBAC      │  │   Org       │  │  Job Ownership      ││
│  │   (Roles)   │  │   Check     │  │  Validation         ││
│  └─────────────┘  └─────────────┘  └─────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                    DADOS                                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐│
│  │   TLS 1.3   │  │   Encrypted │  │  Secrets Manager    ││
│  │   (Transit) │  │   at Rest   │  │  (Environment)      ││
│  └─────────────┘  └─────────────┘  └─────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

## 3. Componentes de Segurança

### 3.1 SecurityShieldMiddleware (`security_shield.py`)

Responsável por:
- JWT validation com JWKS cache
- Rate limiting via Redis
- SSRF protection com IP allowlist
- Security headers injection

**Melhoriasplanejadas:**
- Timing-safe token comparison
- Explicit CORS origin validation
- Enhanced SSRF bypass prevention

### 3.2 Authentication Service (`app.py`)

- Supabase JWT verification
- API Key authentication
- Token comparison (ATUALIZAR para timing-safe)

### 3.3 Secrets Management

| Secret | Requisito | Implementação |
|--------|-----------|---------------|
| API_KEY_SECRET | 256-bit entropy | `secrets.token_hex(32)` |
| SUPABASE_JWT_SECRET | Base64 256-bit+ | Environment only |
| SCANNER_ENCRYPTION_KEY | 256-bit | `secrets.token_urlsafe(24)` |

## 4. Padrões de Implementação

### 4.1 Comparação de Secrets (Timing-Safe)

```python
# ANTES (VULNERÁVEL)
if token == API_KEY_SECRET:
    return "api_key_user"

# DEPOIS (SEGURO)
import secrets
if secrets.compare_digest(token, API_KEY_SECRET):
    return "api_key_user"
```

### 4.2 Validação de Secrets em Startup

```python
def validate_required_secrets():
    required = [
        "API_KEY_SECRET",
        "SUPABASE_JWT_SECRET",
    ]
    missing = [s for s in required if not os.getenv(s)]
    if missing:
        if os.getenv("ENVIRONMENT") == "production":
            raise RuntimeError(f"Missing required secrets: {missing}")
        # Generate for development
        for s in missing:
            os.environ[s] = secrets.token_hex(32)
```

### 4.3 CORS Seguro

```python
allowed_origins = os.getenv("ALLOWED_ORIGINS", "").split(",")
if "*" in allowed_origins:
    raise ValueError("Cannot use '*' origin with credentials=True")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
```

## 5. Lista de ADRs

| ADR | Título | Status |
|-----|--------|--------|
| ADR-001 | Use secrets.token_hex for API key generation | Proposed |
| ADR-002 | Timing-safe token comparison | Proposed |
| ADR-003 | Explicit CORS origin validation | Proposed |
| ADR-004 | Required secrets validation at startup | Proposed |
| ADR-005 | Remove secrets from .env.example | Proposed |

## 6. Checklists de Segurança

### 6.1 Pre-Commit
- [ ] Secrets não commitados
- [ ] .gitignore verifica .env
- [ ] .env.example sem valores reais

### 6.2 Pre-Deploy
- [ ] ENVIRONMENT=production
- [ ] Todos os secrets configurados
- [ ] TLS 1.3 habilitado
- [ ] Rate limiting ativo

---

**Criado:** 2026-03-25  
**Versão:** 1.0  
**Architect:** Security Review Agent
