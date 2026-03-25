# test_celery_connection.py - Valida conexão Celery → Redis
import sys
import os

# Adiciona ao path para importar app
sys.path.insert(0, os.path.abspath("."))

try:
    from app import celery
    from celery.result import AsyncResult
    print("[*] Celery app carregado com sucesso.")
except ImportError as e:
    print(f"[!] Erro ao importar Celery app: {e}")
    sys.exit(1)

def check_worker_status():
    print("[*] Verificando conexão com Redis e presença de workers...")
    try:
        # Testa broker
        conn = celery.connection().connect()
        print(f"[+] Conexão com Broker (Redis) OK: {celery.conf.broker_url}")
        conn.release()

        # Verifica workers ativos
        inspect = celery.control.inspect()
        active = inspect.active()
        if not active:
            print("[!] NENHUM worker ativo encontrado. Verifique se o container celery-worker está rodando.")
            return False
        
        print(f"[+] Workers ativos: {list(active.keys())}")
        
        # Lista tasks registradas
        registered = inspect.registered()
        print("[*] Tasks registradas no worker:")
        for worker, tasks in registered.items():
            for t in tasks:
                if 'scanner.scan_api' in t:
                    print(f"  - {t} [ENCONTRADA ✅]")
                else:
                    print(f"  - {t}")
        return True
    except Exception as e:
        print(f"[!] Erro ao inspecionar worker: {e}")
        return False

if __name__ == "__main__":
    if check_worker_status():
        print("\n[SUCCESS] Celery está configurado e o worker está pronto para receber tasks.")
    else:
        print("\n[FAILURE] Existem problemas na conexão ou registro do Celery.")
        sys.exit(1)
