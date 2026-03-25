#!/bin/bash

# Cores para o output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "🚀 Iniciando teste de correção do WebSocket..."

# 1. Sobe infraestrutura
echo "📦 Subindo containers (docker compose)..."
docker compose up -d --build

# 2. Aguarda saúde dos serviços
echo "⏳ Aguardando serviços estarem prontos (max 30s)..."
COUNTER=0
until $(curl -sf http://localhost:8000/health > /dev/null) || [ $COUNTER -eq 30 ]; do
    printf '.'
    sleep 1
    COUNTER=$((COUNTER+1))
done
echo ""

if [ $COUNTER -eq 30 ]; then
    echo -e "${RED}FAIL: Servidores não iniciaram a tempo.${NC}"
    exit 1
fi

echo -e "${GREEN}PASS: Servidores Online.${NC}"

# Define um JOB_ID para teste
JOB_ID="test-fix-ws-$(date +%s)"
TOKEN="super-secret-local-key"

# 3. Teste WebSocket DIRETO (Porta 8000)
echo "🔍 Testando WebSocket Direto (App :8000)..."
# Inicia em background e tenta enviar o token para autenticar
(sleep 2; echo '{"token": "'$TOKEN'"}'; sleep 30) | timeout 35s wscat -c ws://localhost:8000/ws/logs/$JOB_ID > ws_direct.log 2>&1 &
WS_PID=$!
wait $WS_PID

if grep -q "heartbeat" ws_direct.log; then
    echo -e "${GREEN}PASS: WebSocket Direto Conectado + Heartbeat Recebido.${NC}"
else
    echo -e "${RED}FAIL: WebSocket Direto não recebeu heartbeat ou falhou.${NC}"
    cat ws_direct.log
fi

# 4. Teste WebSocket via NGINX (Porta 80)
echo "🔍 Testando WebSocket via Nginx (Proxy :80)..."
(sleep 2; echo '{"token": "'$TOKEN'"}'; sleep 30) | timeout 35s wscat -c ws://localhost/ws/logs/$JOB_ID > ws_nginx.log 2>&1 &
WS_PID_NGINX=$!
wait $WS_PID_NGINX

if grep -q "heartbeat" ws_nginx.log; then
    echo -e "${GREEN}PASS: WebSocket Nginx Conectado + Heartbeat Recebido.${NC}"
else
    echo -e "${RED}FAIL: WebSocket Nginx não recebeu heartbeat ou falhou.${NC}"
    cat ws_nginx.log
fi

# 5. Teste Token Inválido
echo "🔍 Testando Token Inválido..."
(sleep 2; echo '{"token": "invalid-token"}'; sleep 5) | wscat -c ws://localhost/ws/logs/$JOB_ID > ws_invalid.log 2>&1
if grep -q "1008" ws_invalid.log || grep -q "Unauthorized" ws_invalid.log; then
    echo -e "${GREEN}PASS: Token inválido rejeitado corretamente (Close 1008).${NC}"
else
    echo -e "${RED}FAIL: Token inválido não foi bloqueado corretamente.${NC}"
    cat ws_invalid.log
fi

# Limpeza opcional
# docker compose down

echo "✅ Todos os testes básicos finalizados."
