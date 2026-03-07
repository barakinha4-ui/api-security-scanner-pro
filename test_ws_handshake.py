"""
Script de verificação do handshake WS do dashboard.html
Simula exatamente o que o dashboard.html faz:
1. Cria um scan (obtém job_id)
2. Conecta via WebSocket ao job_id
3. Envia o token como primeira mensagem JSON: {"token": "..."}
4. Escuta por 30 segundos, exibindo tudo
"""
import asyncio
import json
import requests
import websockets

API_BASE = "http://localhost:8000"
WS_BASE = "ws://localhost:8000"
API_KEY = "super-secret-local-key"
TARGET = "http://localhost:9000"
HEADERS = {"Authorization": f"Bearer {API_KEY}"}


async def run():
    # 1. Cria scan
    print("[*] Disparando novo scan...")
    resp = requests.post(f"{API_BASE}/api/scan", json={"target": TARGET, "scan_type": "quick"}, headers=HEADERS)
    if resp.status_code != 202:
        print(f"[ERRO] Falha ao criar scan: {resp.status_code} - {resp.text}")
        return
    
    job_id = resp.json()["job_id"]
    print(f"[OK] Scan criado com Job ID: {job_id}")

    # 2. Conecta via WebSocket
    ws_url = f"{WS_BASE}/ws/logs/{job_id}"
    print(f"[*] Conectando ao WebSocket: {ws_url}")
    
    async with websockets.connect(ws_url) as ws:
        # 3. Handshake (exatamente como o dashboard.html faz)
        auth_msg = json.dumps({"token": API_KEY})
        await ws.send(auth_msg)
        print(f"[OK] Handshake enviado: {auth_msg}")

        # 4. Escuta por até 60 segundos
        print("[*] Monitorando eventos por 60 segundos...\n")
        try:
            async for msg in ws:
                data = json.loads(msg)
                msg_type = data.get("type", data.get("status", "unknown"))
                
                if msg_type == "finding":
                    f = data.get("data", {})
                    print(f"  [🚨 VULNERABILIDADE] {f.get('severity')} - {f.get('title')}")
                    print(f"     Endpoint: {f.get('endpoint')}")
                    print(f"     CVSS: {f.get('cvss_score')}")
                elif msg_type == "running":
                    print(f"  [▶] Status: RUNNING")
                elif msg_type == "completed":
                    print(f"  [✅] Status: COMPLETED")
                    summary = data.get("summary", {})
                    if summary:
                        print(f"     Total Findings: {summary.get('total', 0)}")
                    break
                else:
                    print(f"  [INFO] {json.dumps(data)}")
        except websockets.exceptions.ConnectionClosedError as e:
            print(f"[ERRO] Conexão WebSocket fechada: code={e.code}, reason={e.reason}")

if __name__ == "__main__":
    asyncio.run(run())
