# monitor_worker.sh - Tail dos logs do worker em tempo real
# Usa cores para destacar eventos importantes do Celery

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}[*] Monitorando logs do Celery Worker... (Ctrl+C para sair)${NC}"

docker compose logs -f celery-worker | while read line; do
    if [[ $line == *"Received task"* ]]; then
        echo -e "${CYAN}$line${NC}"
    elif [[ $line == *"succeeded in"* ]]; then
        echo -e "${GREEN}$line${NC}"
    elif [[ $line == *"Task scanner.scan_api"* ]]; then
        echo -e "${YELLOW}$line${NC}"
    elif [[ $line == *"ERROR"* ]] || [[ $line == *"failed"* ]]; then
        echo -e "${RED}$line${NC}"
    else
        echo "$line"
    fi
done
