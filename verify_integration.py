import requests
import time
import json
import traceback

API_URL = "http://localhost:8000"
TARGET_URL = "http://localhost:9000"
API_KEY = "super-secret-local-key"

def verify():
    print(f"[*] Starting verification against {API_URL}")
    print(f"[*] Target: {TARGET_URL}")
    
    headers = {"Authorization": f"Bearer {API_KEY}"}
    
    try:
        # 1. Trigger Scan
        payload = {
            "target": TARGET_URL,
            "scan_type": "quick"
        }
        
        response = requests.post(f"{API_URL}/api/scan", json=payload, headers=headers)
        if response.status_code != 202:
            print(f"[!] Failed to trigger scan: {response.text}")
            return
        
        job_id = response.json()["job_id"]
        print(f"[*] Job Queued: {job_id}")
        
        # 2. Poll Status
        max_retries = 60
        for i in range(max_retries):
            try:
                response = requests.get(f"{API_URL}/api/jobs/{job_id}", headers=headers)
                if response.status_code != 200:
                    print(f"[!] Failed to get status: {response.text}")
                    break
                    
                data = response.json()
                status = data["status"]
                print(f"[*] Status: {status} ({i+1}/{max_retries})")
                
                if status == "completed":
                    print("[+] Scan Completed!")
                    break
                elif status == "failed":
                    print(f"[!] Scan Failed: {data.get('error')}")
                    break
            except Exception as e:
                print(f"[!] Request error during polling: {e}")
                
            time.sleep(2)
        else:
            print("[!] Timeout waiting for scan completion")
            return

        # 3. Get Results
        response = requests.get(f"{API_URL}/api/jobs/{job_id}/results", headers=headers)
        if response.status_code == 200:
            results = response.json()
            print("\n[+] Scan Results Summary:")
            print(json.dumps(results.get("summary"), indent=2))
            
            findings = results.get("findings", [])
            print(f"\n[+] Findings Count: {len(findings)}")
            for f in findings:
                print(f"  - [{f.get('severity')}] {f.get('title')} at {f.get('endpoint')}")
        else:
            print(f"[!] Failed to get results: {response.status_code} - {response.text}")
            
    except Exception:
        traceback.print_exc()

if __name__ == "__main__":
    verify()
