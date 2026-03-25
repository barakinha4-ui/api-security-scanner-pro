import httpx
import asyncio

async def main():
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "http://localhost/api/scan",
            headers={"Authorization": "Bearer super-secret-local-key"},
            json={"target": "http://scanme.nmap.org", "scan_type": "quick"}
        )
        print(f"Status: {resp.status_code}")
        print(f"Body: {resp.text}")

if __name__ == "__main__":
    asyncio.run(main())
