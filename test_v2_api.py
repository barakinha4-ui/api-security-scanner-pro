import requests
import json
import time

url = "http://localhost:8000/api/scan"
headers = {
    "Authorization": "Bearer Gustavo2024ScannerPro!",
    "Content-Type": "application/json"
}
data = {
    "target": "http://vulnerable-api-lab:9000/api/v1/users/1",
    "scan_type": "custom",
    "plugins": ["idor"],
    "headers": {"Authorization": "Bearer TOKEN_VICTIM"}
}

print("Starting scan...")
response = requests.post(url, headers=headers, json=data)
print("Status:", response.status_code)
print("Response:", response.json())

if response.status_code == 202:
    job_id = response.json().get("job_id")
    print(f"Job ID: {job_id}")
    
    # Poll for results
    for _ in range(30):
        time.sleep(2)
        res = requests.get(f"http://localhost:8000/api/jobs/{job_id}", headers=headers)
        if res.status_code == 200:
            status = res.json().get("status")
            print(f"Status check: {status}")
            if status in ["completed", "failed"]:
                print(json.dumps(res.json(), indent=2))
                
                # Fetch full results
                full_res = requests.get(f"http://localhost:8000/api/jobs/{job_id}/results", headers=headers)
                if full_res.status_code == 200:
                    print("Full Results:")
                    print(json.dumps(full_res.json(), indent=2))
                break
