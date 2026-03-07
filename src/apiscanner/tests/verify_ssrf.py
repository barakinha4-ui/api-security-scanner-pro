
import asyncio
import sys
import os

# Add src to path
sys.path.append(os.path.join(os.getcwd(), "src", "apiscanner"))

from core.engine import AsyncEngine

async def verify_ssrf():
    print("[*] Testing SSRF Protection...")
    
    targets = [
        "http://127.0.0.1:8000",
        "http://localhost:80",
        "http://169.254.169.254/latest/meta-data/",
        "http://192.168.1.1",
        "https://google.com" # Should pass
    ]
    
    engine = AsyncEngine(allow_internal=False)
    
    async with engine:
        for t in targets:
            print(f"[*] Probing {t}...")
            resp = await engine.get(t)
            if resp.error == "SSRF_PROTECTION_TRIGGERED":
                print(f"    [OK] Correctly blocked internal target: {t}")
            elif not resp.ok and "google" in t:
                # Might fail if no internet, but logic is fine
                print(f"    [OK] External request attempted: {t}")
            elif resp.ok and "google" in t:
                print(f"    [OK] External request successful: {t}")
            else:
                print(f"    [!] FAILED: Request to {t} was NOT blocked.")

if __name__ == "__main__":
    asyncio.run(verify_ssrf())
