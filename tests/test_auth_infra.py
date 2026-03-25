import httpx
import asyncio
import os
from dotenv import load_dotenv

load_dotenv()

BASE_URL = "http://localhost"
LOCAL_KEY = os.getenv("API_KEY_SECRET", "super-secret-local-key")

async def test_local_auth():
    print(f"--- Testing Local API Key Auth ---")
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                f"{BASE_URL}/api/scan",
                headers={"Authorization": f"Bearer {LOCAL_KEY}"},
                json={"target": "http://example.com"}
            )
            print(f"Status: {resp.status_code}")
            print(f"Body: {resp.text}")
            if resp.status_code == 200:
                print("✅ Local Auth Success!")
            else:
                print("❌ Local Auth Failed!")
        except Exception as e:
            print(f"❌ Connection Error: {e}")

async def test_invalid_token():
    print(f"\n--- Testing Invalid Token Auth ---")
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{BASE_URL}/api/scan",
            headers={"Authorization": "Bearer Invalid.Token.Here"},
            json={"target": "http://example.com"}
        )
        print(f"Status: {resp.status_code}")
        if resp.status_code == 401:
            print("✅ Invalid Token correctly rejected!")
        else:
            print("❌ Invalid Token check failed!")

async def test_ssrf_protection():
    print(f"\n--- Testing SSRF Protection ---")
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{BASE_URL}/api/scan",
            headers={"Authorization": f"Bearer {LOCAL_KEY}"},
            json={"target": "http://169.254.169.254"}
        )
        print(f"Status: {resp.status_code}")
        if resp.status_code == 403:
            print("✅ SSRF Protection Active (Blocked 169.254.169.254)!")
        else:
            print("❌ SSRF Protection Failed!")

if __name__ == "__main__":
    asyncio.run(test_local_auth())
    asyncio.run(test_invalid_token())
    asyncio.run(test_ssrf_protection())
