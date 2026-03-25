# 🚀 Quick Start - API Security Scanner Pro

## Pré-requisitos

- Docker e Docker Compose
- Node.js 18+ (para desenvolvimento local do frontend)
- Python 3.11+ (para desenvolvimento local)

---

## Setup em 5 Passos

### Passo 1: Configure as variáveis de ambiente

```bash
# Copie o arquivo de exemplo
cp .env.example .env

# Edite o .env com suas credenciais
nano .env
```

**Variáveis obrigatórias:**
```env
# Supabase (crie em https://supabase.com)
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-anon-key
SUPABASE_JWT_SECRET=your-jwt-secret

# Auth Keys (gere com: python -c "import secrets; print(secrets.token_hex(32))")
API_KEY_SECRET=your-generated-secret
SCANNER_ENCRYPTION_KEY=your-encryption-key
```

### Passo 2: Configure o Banco de Dados

1. Crie um projeto em https://supabase.com
2. Execute o SQL em `supabase/schema.sql` no SQL Editor
3. Copie as credenciais para o .env

### Passo 3: Inicie a infraestrutura

```bash
# Desenvolvimento local
docker-compose up -d

# Ou com produção
docker-compose -f docker-compose.production.yml up -d
```

### Passo 4: Acesse os serviços

| Serviço | URL |
|---------|-----|
| Frontend | http://localhost:3000 |
| API | http://localhost:8000 |
| WebSocket | ws://localhost:8765 |
| Nginx | http://localhost:80 |
| Grafana | http://localhost:3001 |

### Passo 5: Configure o Frontend

```bash
cd frontend
cp .env.example .env.local
# Edite com suas credenciais Supabase

npm install
npm run dev
```

---

## Arquitetura dos Serviços

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Frontend   │────▶│  FastAPI    │────▶│    Redis     │
│  (Next.js)   │     │   (app)     │     │  (Queue)     │
└──────────────┘     └──────────────┘     └──────────────┘
                            │                    │
                            ▼                    ▼
                     ┌──────────────┐     ┌──────────────┐
                     │  WebSocket   │     │   Celery     │
                     │    (ws)      │     │   Worker     │
                     └──────────────┘     └──────────────┘
                                                  │
                                                  ▼
                                           ┌──────────────┐
                                           │   Supabase    │
                                           │  (Database)   │
                                           └──────────────┘
```

---

## Comandos Úteis

```bash
# Ver logs
docker-compose logs -f app
docker-compose logs -f worker

# Reiniciar serviços
docker-compose restart app worker

# Escalar workers
docker-compose up -d --scale worker=3

# Parar tudo
docker-compose down
```

---

## Troubleshooting

### Redis não conecta?
```bash
# Verifique se o Redis está rodando
docker-compose ps
docker-compose logs redis
```

### Supabase auth falha?
```bash
# Verifique as credenciais no .env
# Recrie o projeto Supabase se necessário
```

### Celery worker não consome tarefas?
```bash
# Verifique a conexão com Redis
docker-compose exec worker celery -A tasks inspect active
```
