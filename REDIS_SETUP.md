# Redis Configuration for API Security Scanner Pro

## Opções de Redis

### Opção A: Redis Local (Desenvolvimento)

```bash
# Docker
docker run -d --name redis -p 6379:6379 redis:7-alpine

# Ou local
brew install redis
redis-server
```

### Opção B: Redis Cloud (Produção)

Recomendado: **Upstash** ou **Redis Cloud**

1. **Upstash** (Free tier disponível):
   - Acesse: https://upstash.com
   - Crie database Redis
   - Copie a URL: `redis://default:xxxx@xxxx.upstash.io:6379`

2. **Redis Cloud** (Supabase Marketplace):
   - No Supabase Dashboard > Marketplace > Redis Cloud
   - Configure o plano free

### Variáveis de Ambiente

```env
# Para desenvolvimento local
REDIS_URL=redis://localhost:6379/0
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# Para Upstash/Cloud
REDIS_URL=redis://default:password@host.upstash.io:6379
```

### Testando Conexão

```python
from redis_config import ping_redis
import asyncio

async def test():
    ok, latency = await ping_redis()
    print(f"Redis: {ok}, Latency: {latency}ms")

asyncio.run(test())
```
