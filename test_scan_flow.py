import requests
import time
import sys
import os

# test_scan_flow.py - Testa o fluxo completo: Trigger -> Celery -> Redis -> Status
API_URL = os.getenv("API_URL", "http://localhost:8000")
API_KEY = "super-secret-local-key"
TARGET = "https://1.1.1.1" # IP público estável para evitar bloqueio DNS/SSRF

def run_test():
    headers = {"Authorization": f"Bearer {API_KEY}"}
    
    print(f"[*] 1. Disparando scan para {TARGET}...")
    try:
        resp = requests.post(
            f"{API_URL}/api/scan",
            json={"target": TARGET, "scan_type": "quick"},
            headers=headers
        )
        if resp.status_code != 202:
            print(f"[!] Erro ao iniciar scan: {resp.text}")
            return False
        
        job_id = resp.json().get("job_id")
        print(f"[+] Scan enfileirado! Job ID: {job_id}")

        print("[*] 2. Monitorando status (polling)...")
        for i in range(30): # 60 segundos timeout (2s cada)
            status_resp = requests.get(f"{API_URL}/api/status/{job_id}", headers=headers)
            if status_resp.status_code != 200:
                print(f"[!] Erro ao consultar status: {status_resp.text}")
                break
            
            data = status_resp.json()
            status = data.get("status")
            celery_state = data.get("celery_state", "N/A")
            print(f"  [{i+1}/30] Status: {status} | Celery: {celery_state}")

            if status == "completed":
                print("\n[SUCCESS] Fluxo completo validado com sucesso!")
                return True
            if status == "failed":
                print(f"\n[FAILURE] Scan falhou: {data.get('error')}")
                return False
            
            time.sleep(2)
        
        print("\n[TIMEOUT] O scan demorou demais para completar.")
        return False

    except Exception as e:
        print(f"[!] Erro de execução do script: {e}")
        return False

if __name__ == "__main__":
    if run_test():
        sys.exit(0)
    else:
        sys.exit(1)
