import json
import os

try:
    with open('last_scan.json', 'r', encoding='utf-16') as f:
        data = json.load(f)
    
    if not data:
        print("No scans found.")
        exit()
        
    last = data[-1]
    print(f"Scan ID: {last.get('id')}")
    print(f"Status: {last.get('status')}")
    
    result = last.get('result')
    if result:
        findings = result.get('findings', [])
        print(f"Findings Count: {len(findings)}")
        for f in findings:
            confirm_str = "[CONFIRMED]" if f.get('confirmed') else ""
            print(f"- [{f.get('severity')}] {f.get('title')} {confirm_str}")
    else:
        print("No result data yet.")

except Exception as e:
    print(f"Error: {e}")
