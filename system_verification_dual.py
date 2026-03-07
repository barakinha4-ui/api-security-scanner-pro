import requests
import sys
import time
import json

API_URL = "http://localhost:8000"
TARGET_URL = "http://localhost:9000"
API_KEY = "super-secret-local-key"
HEADERS = {"Authorization": f"Bearer {API_KEY}"}

def run_test_1():
    """Teste 1: Verificação de Saúde e Autenticação"""
    print("\n[TESTE 1] Verificando Saúde e Autenticação...")
    
    # 1.1 Health Check
    try:
        resp = requests.get(f"{API_URL}/health")
        if resp.status_code == 200:
            print("  [OK] Health check status 200")
        else:
            print(f"  [ERRO] Health check falhou: {resp.status_code}")
            return False, f"Health check falhou (Status {resp.status_code})"
    except Exception as e:
        return False, f"Falha na conexão com o servidor: {e}"

    # 1.2 Auth Check (Token Inválido)
    resp = requests.get(f"{API_URL}/api/jobs/dummy", headers={"Authorization": "Bearer TOKEN_INVALIDO"})
    if resp.status_code == 401:
        print("  [OK] Autenticação bloqueou token inválido")
    else:
        print(f"  [ERRO] Autenticação aceitou token inválido ou retornou erro inesperado: {resp.status_code}")
        return False, "Falha na segurança: Autenticação não bloqueou token inválido"

    # 1.3 Auth Check (Token Válido)
    resp = requests.get(f"{API_URL}/api/jobs/dummy", headers=HEADERS)
    if resp.status_code == 404: # Dummy job não existe, mas 404 significa que passou pelo auth
        print("  [OK] Autenticação validou API Key corretamente")
    else:
        print(f"  [ERRO] API Key válida não foi aceita ou erro inesperado: {resp.status_code}")
        return False, "Falha no acesso: API Key válida falhou"

    return True, "Teste 1 concluído com sucesso"

def run_test_2():
    """Teste 2: Ciclo Completo de Scan"""
    print("\n[TESTE 2] Verificando Ciclo Completo de Scan...")

    # 2.1 Enviar Job
    payload = {"target": TARGET_URL, "scan_type": "quick"}
    try:
        resp = requests.post(f"{API_URL}/api/scan", json=payload, headers=HEADERS)
        if resp.status_code == 202:
            job_id = resp.json()["job_id"]
            print(f"  [OK] Scan iniciado com sucesso. Job ID: {job_id}")
        else:
            return False, f"Falha ao iniciar scan: {resp.status_code} - {resp.text}"
    except Exception as e:
        return False, f"Erro ao enviar requisição de scan: {e}"

    # 2.2 Polling de Status
    max_wait = 60
    for i in range(max_wait):
        resp = requests.get(f"{API_URL}/api/jobs/{job_id}", headers=HEADERS)
        status = resp.json()["status"]
        if status == "completed":
            print("  [OK] Scan finalizado com sucesso")
            break
        elif status == "failed":
            return False, f"O scan falhou internamente: {resp.json().get('error')}"
        time.sleep(2)
    else:
        return False, "Timeout: O scan demorou mais de 120 segundos"

    # 2.3 Verificar Resultados
    resp = requests.get(f"{API_URL}/api/jobs/{job_id}/results", headers=HEADERS)
    if resp.status_code == 200:
        results = resp.json()
        findings = results.get("findings", [])
        if len(findings) > 0:
            print(f"  [OK] Resultados obtidos: {len(findings)} vulnerabilidades encontradas")
        else:
            print("  [AVISO] Scan concluído mas nenhum resultado encontrado (esperado em targets seguros)")
    else:
        return False, f"Falha ao obter resultados: {resp.status_code}"

    return True, "Teste 2 concluído com sucesso"

if __name__ == "__main__":
    tests = [run_test_1, run_test_2]
    
    for i, test in enumerate(tests, 1):
        success, message = test()
        if not success:
            print(f"\n--- RELATÓRIO DE ERRO ---")
            print(f"Falha no Teste {i}")
            print(f"Mensagem: {message}")
            sys.exit(1)
    
    print("\n--- RELATÓRIO FINAL ---")
    print("Todos os testes passaram com sucesso!")
    sys.exit(0)
